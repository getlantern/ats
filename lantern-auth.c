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
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
    goto done;
  }

  val = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, field_loc, -1, &authval_length);
  if (NULL == val) {
    TSError("no value in %s field\n", AUTH_HEADER);
    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
    goto done;
  }

  if (strncmp(val, auth_token, auth_token_len) != 0) {
    TSError("lantern customized token mismatch\n");
    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
    goto done;
  }

  TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return;

done:
  TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_ERROR);
}

  static void
handle_response(TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    TSError("couldn't retrieve client response header\n");
  }
  TSHttpHdrStatusSet(bufp, hdr_loc, TS_HTTP_STATUS_FORBIDDEN);
  TSHttpHdrReasonSet(bufp, hdr_loc, status_forbidden, status_forbidden_len);
  // intentionally not return any content

  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
}


  static int
auth_plugin(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn)edata;

  switch (event) {
    case TS_EVENT_HTTP_OS_DNS:
      handle_dns(txnp, contp);
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

  TSHttpHookAdd(TS_HTTP_OS_DNS_HOOK, TSContCreate(auth_plugin, NULL));
}
