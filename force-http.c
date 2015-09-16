/** @file

	A plugin that forces HTTP to origin server if request method is not CONNECT

 */


#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include "ts/ts.h"
#include "ink_defs.h"

				static void
handle_request(TSHttpTxn txnp, TSCont contp)
{
				TSMBuffer bufp;
				TSMLoc hdr_loc;
				TSMLoc url_loc;
				const char *method, *scheme;
				int method_length, scheme_length;
				int port;

				if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
								TSError("couldn't retrieve client request header\n");
								goto done;
				}

				method = TSHttpHdrMethodGet(bufp, hdr_loc, &method_length);
				if (!method) {
								TSError("couldn't retrieve request method\n");
								goto clear_hdr;
				}
				if (strncmp(method, "CONNECT", method_length) == 0) {
								goto clear_hdr;
				}
				if (TSHttpHdrUrlGet(bufp, hdr_loc, &url_loc) != TS_SUCCESS) {
								TSError("couldn't retrieve request url\n");
								goto clear_hdr;
				}

				scheme = TSUrlSchemeGet(bufp, url_loc, &scheme_length);
				if (!scheme) {
								TSError("couldn't retrieve request schemename\n");
								goto clear_url;
				}
				if (TSUrlSchemeSet(bufp, url_loc, "http", -1) != TS_SUCCESS) {
								TSError("couldn't set request scheme\n");
								goto clear_url;
				}
				port = TSUrlPortGet(bufp, url_loc);
				if (!port) {
								TSError("couldn't retrieve request port\n");
								goto clear_url;
				}
				if (TSUrlPortSet(bufp, url_loc, 80) != TS_SUCCESS) {
								TSError("couldn't set request port\n");
								goto clear_url;
				}
				if (TSHttpHdrUrlSet(bufp, hdr_loc, url_loc) != TS_SUCCESS) {
								TSError("couldn't set request url\n");
								goto clear_url;
				}
				TSError("set scheme from %s to http for method %s\n", scheme, method);
				TSError("set port from %d to 80 for method %s\n", port, method);
clear_url:
				TSHandleMLocRelease(bufp, hdr_loc, url_loc);
clear_hdr:
				TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
done:
				TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
}

				static int
force_http_plugin(TSCont contp, TSEvent event, void *edata)
{
				TSHttpTxn txnp = (TSHttpTxn)edata;

				switch (event) {
								case TS_EVENT_HTTP_READ_REQUEST_HDR:
												handle_request(txnp, contp);
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

				info.plugin_name = "force-http-to-origin-server";
				info.vendor_name = "BNS";
				info.support_email = "team@getlantern.org";

				if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
								TSError("Plugin registration failed.\n");
								return;
				}

				TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, TSContCreate(force_http_plugin, NULL));
}
