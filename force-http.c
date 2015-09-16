/** @file

  A plugin that performs Lantern customized HTTP header authentication

*/


#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include "ts/ts.h"
#include "ink_defs.h"

const char AUTH_HEADER[] = "X-LANTERN-AUTH-TOKEN";
const char AUTH_HEADER_LEN = sizeof(AUTH_HEADER)/sizeof(char)-1;
const static char* auth_token;
static size_t auth_token_len;
const static char* status_forbidden;
static size_t status_forbidden_len;

  static void
handle_dns(TSHttpTxn txnp, TSCont contp)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  TSMLoc method_loc;
  TSMLoc url_loc;
  const char *method, *host;
  int method_length, host_length;

  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    TSError("couldn't retrieve client request header\n");
    goto done;
  }

  method = TSHttpHdrMethodGet(bufp, hdr_loc, &method_loc)
  if (!method) {
    TSError("couldn't retrieve request method\n");
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
    goto done;
  }

  host = TSUrlGet(bufp, url_loc, &host_length);
  if (!host) {
    TSError("couldn't retrieve request hostname\n");
    TSHandleMLocRelease(bufp, hdr_loc, url_loc);
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
    goto done;
  }

  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return;

done:
  TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
}

  static int
force_http_plugin(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn)edata;

  switch (event) {
    case TS_EVENT_HTTP_READ_REQUEST_HDR:
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
  status_forbidden = TSHttpHdrReasonLookup(TS_HTTP_STATUS_FORBIDDEN);
  status_forbidden_len = strlen(TSHttpHdrReasonLookup(TS_HTTP_STATUS_FORBIDDEN));

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, TSContCreate(force_http_plugin, NULL));
}
