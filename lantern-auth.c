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
		TSError("couldn't retrieve client request header");
		goto done;
	}

	field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, AUTH_HEADER, AUTH_HEADER_LEN);
	if (TS_NULL_MLOC == field_loc) {
		TSError("no %s field", AUTH_HEADER);
		goto print_client_ip;
	}

	val = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, -1, &authval_length);
	if (NULL == val) {
		TSError("no value in %s field", AUTH_HEADER);
		goto clear_field;
	}

	if (authval_length != auth_token_len || strncmp(val, auth_token, auth_token_len) != 0) {
		TSError("lantern customized token mismatch");
		goto clear_field;
	}

	TSHandleMLocRelease(bufp, hdr_loc, field_loc);
	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
	TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
	return;

clear_field:
	TSHandleMLocRelease(bufp, hdr_loc, field_loc);
print_client_ip:
	{
		char ip_str[INET6_ADDRSTRLEN];
		struct sockaddr const *addr = TSHttpTxnClientAddrGet(txnp);
		if (NULL == addr) {
			TSError("couldn't get client ip");
			goto print_host;
		}
		socklen_t addr_size = 0;
		if (addr->sa_family == AF_INET)
			addr_size = sizeof(struct sockaddr_in);
		else if (addr->sa_family == AF_INET6)
			addr_size = sizeof(struct sockaddr_in6);
		if (addr_size == 0) {
			TSError("unsupported address family");
			goto print_host;
		}
		if (NULL == inet_ntop(addr->sa_family, addr, ip_str, addr_size)) {
			TSError("inet_ntop error");
			goto print_host;
		}
		TSError("client ip is %s", ip_str);
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
			TSError("couldn't retrieve request hostname\n");
			TSHandleMLocRelease(bufp, hdr_loc, url_loc);
			goto clear_hdr;
		}
		TSError("requested host is %s", host);
		TSHandleMLocRelease(bufp, hdr_loc, url_loc);

	}
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
