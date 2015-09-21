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

const char AUTH_HEADER[] = "X-LANTERN-AUTH-TOKEN";
const static char* auth_token;
static size_t auth_token_len;

	static void
handle_lantern_auth(TSHttpTxn txnp, TSCont contp)
{
	TSMBuffer bufp;
	TSMLoc hdr_loc;
	TSMLoc field_loc;
	const char *authval;

	int authval_length;

	if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
		TSError("couldn't retrieve client request header");
		goto done;
	}
	// case insensitive comparasion
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

	if (authval_length != auth_token_len || strncmp(authval, auth_token, auth_token_len) != 0) {
		TSError("lantern auth token mismatch");
		goto clear_field;
	}
	// remove auth header to prevent upstream from seeing it
	if (TSMimeHdrFieldDestroy(bufp, hdr_loc, field_loc) != TS_SUCCESS) {
		TSError("couldn't remove %s header", AUTH_HEADER);
	};
	TSHandleMLocRelease(bufp, hdr_loc, field_loc);
	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
	return;

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
done:
	TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
}

	static void
handle_response(TSHttpTxn txnp)
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
auth_plugin(TSCont contp, TSEvent event, void *edata)
{
	TSHttpTxn txnp = (TSHttpTxn)edata;

	switch (event) {
		case TS_EVENT_HTTP_OS_DNS:
			handle_lantern_auth(txnp, contp);
			return 0;
		case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
			handle_response(txnp);
			return 0;
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
		TSError("Plugin registration failed.");
		return;
	}

	if (argc < 2) {
		TSError("No auth token provided.");
		return;
	}
	auth_token = TSstrdup(argv[1]);
	auth_token_len = strlen(auth_token);

	TSHttpHookAdd(TS_HTTP_OS_DNS_HOOK, TSContCreate(auth_plugin, NULL));
}
