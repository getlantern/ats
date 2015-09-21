/** @file

  A plugin that performs Lantern token based HTTP authentication

 */


#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ts/ts.h"
#include "ink_defs.h"

#define MAX_TOKENS 100
#define RETRY_TIME 10


typedef struct contp_data {
  enum calling_func {
    HANDLE_DNS,
    HANDLE_RESPONSE,
    READ_TOKEN_LIST,
  } cf;

  TSHttpTxn txnp;

} cdata;

typedef struct token_t {
        char *value;
        size_t length;
} token_t;

const char AUTH_HEADER[] = "X-LANTERN-AUTH-TOKEN";
static token_t tokens[MAX_TOKENS];
static int n_tokens;

static TSMutex tokens_mutex;
static TSCont global_contp;


static void
read_token_list(TSCont contp)
{
        char tokens_file[1024];
        TSFile file;

        sprintf(tokens_file, "%s/tokens.txt", TSPluginDirGet());
        file = TSfopen(tokens_file, "r");
        n_tokens = 0;

        /* If the Mutext lock is not successful try again in RETRY_TIME */
        if (TSMutexLockTry(tokens_mutex) != TS_SUCCESS) {
                if (file != NULL) {
                        TSfclose(file);
                }
                TSContSchedule(contp, RETRY_TIME, TS_THREAD_POOL_DEFAULT);
                return;
        }

        if (file != NULL) {
                char buffer[1024];

                while (TSfgets(file, buffer, sizeof(buffer) - 1) != NULL && n_tokens < MAX_TOKENS) {
                        char *eol;
                        if ((eol = strstr(buffer, "\r\n")) != NULL) {
                                /* To handle newlines on Windows */
                                *eol = '\0';
                        } else if ((eol = strchr(buffer, '\n')) != NULL) {
                                *eol = '\0';
                        } else {
                                /* Not a valid line, skip it */
                                continue;
                        }
                        if (tokens[n_tokens].value != NULL) {
                                TSfree(tokens[n_tokens].value);
                        }
                        tokens[n_tokens] = (token_t){
                                TSstrdup(buffer),
                                strlen(buffer)
                        };
                        n_tokens++;
                }

                TSfclose(file);
        } else {
                TSError("[lantern-plugin] Unable to open %s. Tokens list won't be updated.", tokens_file);
        }

        TSMutexUnlock(tokens_mutex);
}

static void
handle_lantern_auth(TSHttpTxn txnp, TSCont contp)
{
	TSMBuffer bufp;
	TSMLoc hdr_loc;
	TSMLoc field_loc;
	const char *authval;
        int i;

	int authval_length;

	if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
		TSError("couldn't retrieve client request header");
		goto reply_error;
	}
	// Case insensitive comparison
	field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, AUTH_HEADER, -1);
	if (TS_NULL_MLOC == field_loc) {
		TSError("no %s field", AUTH_HEADER);
		goto print_client_ip;
	}

	authval = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, -1, &authval_length);
	if (NULL == authval) {
		TSError("no value in %s field", AUTH_HEADER);
		goto clear_field;
	}

        // Check all tokens
        for (i = 0; i < n_tokens; i++) {
                if (authval_length == tokens[i].length &&
                    strncmp(authval, tokens[i].value, tokens[i].length) == 0) {
                        goto reply_ok;
                }
        }
        TSError("lantern auth token mismatch");
        goto clear_field;

        /* OK handling section */
reply_ok:
	// remove auth header to prevent upstream from seeing it
	if (TSMimeHdrFieldDestroy(bufp, hdr_loc, field_loc) != TS_SUCCESS) {
		TSError("couldn't remove %s header", AUTH_HEADER);
	};
	TSHandleMLocRelease(bufp, hdr_loc, field_loc);
	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
	return;

        /* Error handling section */
clear_field:
	TSHandleMLocRelease(bufp, hdr_loc, field_loc);
print_client_ip:
	{
		void *ip;
		char ip_str[INET6_ADDRSTRLEN];
		struct sockaddr const *addr = TSHttpTxnClientAddrGet(txnp);
		const char *ntop_result;
		if (NULL == addr) {
			TSError("couldn't get client ip");
			goto print_host;
		}
		if (addr->sa_family == AF_INET) {
			ip = &(((struct sockaddr_in*)addr)->sin_addr);
			ntop_result = inet_ntop(addr->sa_family, ip, ip_str, sizeof(struct sockaddr_in));
		} else if (addr->sa_family == AF_INET6) {
			ip = &(((struct sockaddr_in6*)addr)->sin6_addr);
			ntop_result = inet_ntop(addr->sa_family, ip, ip_str, sizeof(struct sockaddr_in6));
		} else {
			TSError("unsupported address family");
			goto print_host;
		}
		if (NULL == ntop_result) {
			TSError("inet_ntop error");
			goto print_host;
		}
		TSError("client ip: %s", ip_str);
	}
print_host:
	{
		TSMLoc url_loc;
		const char *host;
		int host_length;
		if (TSHttpHdrUrlGet(bufp, hdr_loc, &url_loc) != TS_SUCCESS) {
			TSError("couldn't retrieve request url.");
			goto clear_hdr;
		}

		host = TSUrlHostGet(bufp, url_loc, &host_length);
		if (NULL == host) {
			TSError("couldn't retrieve request hostname");
			TSHandleMLocRelease(bufp, hdr_loc, url_loc);
			goto clear_hdr;
		}
		TSError("host to visit: %.*s", host_length, host);
		TSHandleMLocRelease(bufp, hdr_loc, url_loc);

	}
clear_hdr:
	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
reply_error:
	TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
}

static void
handle_response(TSHttpTxn txnp, TSCont contp ATS_UNUSED)
{
	const char default_reason[] = "Not Found on Accelerator";
	// Same as /proxy/config/body_factory/default/urlrouting#no_mapping of ATS 5.3.1
	const char default_resp[] = "<HTML>\n<HEAD>\n<TITLE>Not Found on Accelerator</TITLE>\n</HEAD>\n\n<BODY BGCOLOR=\"white\" FGCOLOR=\"black\">\n<H1>Not Found on Accelerator</H1>\n<HR>\n\n<FONT FACE=\"Helvetica,Arial\"><B>\nDescription: Your request on the specified host was not found.\nCheck the location and try again.\n</B></FONT>\n<HR>\n</BODY>\n";
	const struct header {
		const char * const name;
		const char * const value;
	} default_headers[] = {
		{"Cache-Control", "no-store"},
		{"Content-Type", "text/html"},
		{"Content-Language", "en"}
	};
	size_t default_resp_len = sizeof(default_resp)/sizeof(char) - 1;
	TSMBuffer bufp;
	TSMLoc hdr_loc;
	TSMLoc temp_loc;
	int i;
	if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
		TSError("couldn't retrieve client response header");
		return;
	}
	if (TSHttpHdrStatusSet(bufp, hdr_loc, TS_HTTP_STATUS_NOT_FOUND) != TS_SUCCESS) {
		TSError("couldn't set http status code");
	}
	if (TSHttpHdrReasonSet(bufp, hdr_loc, default_reason, -1) != TS_SUCCESS) {
		TSError("couldn't set http status reason");
	}
	temp_loc = TSMimeHdrFieldFind(bufp, hdr_loc, "Connection", -1);
	if (NULL == temp_loc) {
		TSError("No Connection header, should not happen");
	} else if (TSMimeHdrFieldValueStringSet(bufp, hdr_loc, temp_loc, -1, "keep-alive", -1) != TS_SUCCESS) {
		TSError("couldn't set Connection header");
	}
	for (i = 0; i < sizeof(default_headers)/ sizeof(struct header); i++) {
		if (TSMimeHdrFieldCreateNamed(bufp, hdr_loc, default_headers[i].name, -1, &temp_loc) != TS_SUCCESS) {
			TSError("couldn't create %s header", default_headers[i].name);
		} else {
			if (TSMimeHdrFieldValueStringSet(bufp, hdr_loc, temp_loc, -1, default_headers[i].value, -1) != TS_SUCCESS) {
				TSError("couldn't set %s header", default_headers[i].name);
			} else if (TSMimeHdrFieldAppend(bufp, hdr_loc, temp_loc) != TS_SUCCESS) {
				TSError("couldn't append %s header", default_headers[i].name);
			}
		}
	}
	TSHttpTxnErrorBodySet(txnp, TSstrdup(default_resp), default_resp_len, TSstrdup("text/html"));

	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
}

static int
lantern_auth_plugin(TSCont contp, TSEvent event, void *edata)
{
	TSHttpTxn txnp;
        cdata *cd;

	switch (event) {
        case TS_EVENT_HTTP_TXN_START:
                txnp = (TSHttpTxn)edata;
                TSCont txn_contp;

                txn_contp = TSContCreate((TSEventFunc)lantern_auth_plugin, TSMutexCreate());
                /* Create the data that'll be associated with the continuation */
                cd = (cdata *)TSmalloc(sizeof(cdata));
                TSContDataSet(txn_contp, cd);
                cd->txnp = txnp;

                TSHttpTxnHookAdd(txnp, TS_HTTP_OS_DNS_HOOK, txn_contp);
                TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp);

                TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
                return 0;
        case TS_EVENT_HTTP_OS_DNS:
                if (contp != global_contp) {
                        cd = (cdata *)TSContDataGet(contp);
                        cd->cf = HANDLE_DNS;
                        /* Lantern Authentication is done at OS DNS resolution time */
                        handle_lantern_auth(cd->txnp, contp);
                        return 0;
                } else {
                        break;
                }
        case TS_EVENT_HTTP_TXN_CLOSE:
                txnp = (TSHttpTxn)edata;
                if (contp != global_contp) {
                        //destroy_continuation(txnp, contp);
                        cd = (cdata *)TSContDataGet(contp);
                        if (cd != NULL) {
                                TSfree(cd);
                        }
                        TSContDestroy(contp);
                        TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
                }
                break;
        case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
                if (contp != global_contp) {
                        cd = (cdata *)TSContDataGet(contp);
                        cd->cf = HANDLE_RESPONSE;
                        handle_response(cd->txnp, contp);
                        return 0;
                } else {
                        break;
                }
        case TS_EVENT_TIMEOUT:
                /* When mutex lock is not acquired and continuation is rescheduled,
                   the plugin is called back with TS_EVENT_TIMEOUT with a NULL
                   edata. We need to decide, in which function did the MutexLock
                   failed and call that function again */
                if (contp != global_contp) {
                        cd = (cdata *)TSContDataGet(contp);
                        switch (cd->cf) {
                        case HANDLE_DNS:
                                handle_lantern_auth(cd->txnp, contp);
                                return 0;
                        case HANDLE_RESPONSE:
                                handle_response(cd->txnp, contp);
                                return 0;
                        default:
                                TSDebug("lantern_auth", "This event was unexpected: %d\n", event);
                                break;
                        }
                } else {
                        read_token_list(contp);
                        return 0;
                }
        default:
                break;
	}
	return 0;
}

void
TSPluginInit(int argc ATS_UNUSED, const char *argv[] ATS_UNUSED)
{
	TSPluginRegistrationInfo info;

	info.plugin_name = "lantern-token-based-authentication";
	info.vendor_name = "BNS";
	info.support_email = "team@getlantern.org";

	if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
		TSError("[lantern-auth] Plugin registration failed.");
		return;
	}

        tokens_mutex = TSMutexCreate();

        /* By default, use the provided token
           Note: it will be overwritten if tokens.txt is found */
	if (argc < 2) {
		TSError("No auth token provided.");
		return;
	}
	char *auth_token = TSstrdup(argv[1]);
        tokens[0] = (token_t){
                auth_token,
                strlen(auth_token)
        };
        n_tokens = 1;

        global_contp = TSContCreate(lantern_auth_plugin, tokens_mutex);
        read_token_list(global_contp);

	TSHttpHookAdd(TS_HTTP_TXN_START_HOOK, global_contp);
}
