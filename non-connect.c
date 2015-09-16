/** @file

  A plugin that forces HTTP to origin server if request method is not CONNECT

 */


#include <stdio.h>
#include <string.h>

#include <unistd.h>

#include "ts/ts.h"
#include "ts/remap.h"
#include "ink_defs.h"

	TSReturnCode
TSRemapInit(TSRemapInterface *api_info, char *errbuf, int errbuf_size)
{
	return TS_SUCCESS; /* success */
}

	TSReturnCode
TSRemapNewInstance(int argc, char *argv[], void **ih, char *errbuf, int errbuf_size)
{
	return TS_SUCCESS; /* success */
}

	TSRemapStatus
TSRemapDoRemap(void *ih, TSHttpTxn rh, TSRemapRequestInfo *rri)
{
	//TSMLoc host_field;
	/*const char *method, *host;
	int method_len, host_len;
	if (!rri) {
		TSError("rri is nil, should not happen!\n");
		return TSREMAP_NO_REMAP;
	}

	method = TSHttpHdrMethodGet(rri->requestBufp, rri->requestHdrp, &method_len);
	if (!method) {
		TSError("couldn't retrieve request method\n");
		return TSREMAP_NO_REMAP;
	}
	if (strncmp(method, "CONNECT", method_len) == 0) {
		return TSREMAP_NO_REMAP;
	}

	temp = TSUrlHostGet(rri->requestBufp, rri->requestUrl, &temp_len);
	  TSError("[TSRemapDoRemap] Request Host(%d): \"%.*s\"\n", temp_len, temp_len, temp);

	  temp = TSUrlHostGet(rri->requestBufp, rri->mapToUrl, &temp_len);
	  TSError("[TSRemapDoRemap] Remap To Host: \"%.*s\"\n", temp_len, temp);

	  temp = TSUrlHostGet(rri->requestBufp, rri->mapFromUrl, &temp_len);
	  TSError("[TSRemapDoRemap] Remap From Host: \"%.*s\"\n", temp_len, temp);


	host = TSUrlHostGet(rri->requestBufp, rri->requestUrl, &host_len);
	if (!host) {
		TSError("host is nil\n");
		return TSREMAP_NO_REMAP;
	}
	TSError("map https to http for host %s\n", host);

	if (TSUrlHostSet(rri->requestBufp, rri->requestUrl, host, host_len) != TS_SUCCESS) {
	  TSError("failed to set request host\n");
	  return TSREMAP_NO_REMAP;
	  }
	  host_field = TSMimeHdrFieldFind(rri->requestBufp, rri->requestHdrp, TS_MIME_FIELD_HOST, -1);
	  if (host_field == TS_NULL_MLOC) {
	  if (TSMimeHdrFieldCreateNamed(rri->requestBufp, rri->requestHdrp, TS_MIME_FIELD_HOST, -1, &host_field) != TS_SUCCESS) {
	  TSError("couldn't create host field\n");
	  return TSREMAP_NO_REMAP;
	  }
	  }
	  if (TSMimeHdrFieldValueStringSet(rri->requestBufp, rri->requestHdrp, host_field, -1, host, -1) != TS_SUCCESS) {
	  TSError("couldn't set host field\n");
	  return TSREMAP_NO_REMAP;
	  }*/

	return TSREMAP_NO_REMAP;
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
}
