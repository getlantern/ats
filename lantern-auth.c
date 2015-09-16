/** @file

  A plugin that performs Lantern customized HTTP header authentication

 */


#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ts/ts.h"
#include "ink_defs.h"

const char AUTH_HEADER[] = "X-LANTERN-AUTH-TOKEN";
const char AUTH_HEADER_LEN = sizeof(AUTH_HEADER)/sizeof(char)-1;
const static char* auth_token;
static size_t auth_token_len;

	static void
handle_dns(TSHttpTxn txnp, TSCont contp)
{
	TSMBuffer bufp;
	TSMLoc hdr_loc;
	TSMLoc field_loc;
	const char *val;

	int authval_length;

	if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
		TSError("couldn't retrieve client request header\n");
		goto done;
	}

	field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, AUTH_HEADER, AUTH_HEADER_LEN);
	if (!field_loc) {
		TSError("no %s field\n", AUTH_HEADER);
		goto clear_hdr;
	}

	val = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, -1, &authval_length);
	if (NULL == val) {
		TSError("no value in %s field\n", AUTH_HEADER);
		goto clear_field;
	}

	if (strncmp(val, auth_token, auth_token_len) != 0) {
		TSError("lantern customized token mismatch\n");
		goto clear_field;
	}

	TSHandleMLocRelease(bufp, hdr_loc, field_loc);
	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
	return;

clear_field:
	{
		struct sockaddr const *addr = TSHttpTxnClientAddrGet(txnp);
		if (addr) {
			socklen_t addr_size = 0;
			if (addr->sa_family == AF_INET)
				addr_size = sizeof(struct sockaddr_in);
			else if (addr->sa_family == AF_INET6)
				addr_size = sizeof(struct sockaddr_in6);
			if (addr_size > 0) {
				char clientstring[INET6_ADDRSTRLEN];
				if (NULL != inet_ntop(addr->sa_family, addr, clientstring, addr_size))
					TSError("client ip is %s\n", clientstring);
			}
		}
	}
	TSHandleMLocRelease(bufp, hdr_loc, field_loc);
clear_hdr:
	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
done:
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_SSN_CLOSE);
}

	static int
auth_plugin(TSCont contp, TSEvent event, void *edata)
{
	TSHttpTxn txnp = (TSHttpTxn)edata;

	switch (event) {
		case TS_EVENT_HTTP_OS_DNS:
			handle_dns(txnp, contp);
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

	info.plugin_name = "lantern-customized-authentication";
	info.vendor_name = "BNS";
	info.support_email = "team@getlantern.org";

	if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
		TSError("Plugin registration failed.\n");
		return;
	}

	if (argc < 2) {
		TSError("no auth token provided.\n");
		return;
	}
	auth_token = TSstrdup(argv[1]);
	auth_token_len = strlen(auth_token);

	TSHttpHookAdd(TS_HTTP_OS_DNS_HOOK, TSContCreate(auth_plugin, NULL));
}
