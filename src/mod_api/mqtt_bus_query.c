#include <stdlib.h>
#include <unistd.h>
#include <string.h>





#include "mod_api/mqtt_bus_query.h"





PayloadBuf* mbus_query(struct MBusHandle* fp, const char* topic, int rsp_cnt,  int timeout, PayloadBuf* payload)
{
	if (!fp || !topic) {
		return NULL;
	}
	struct MBusQueryParam param = {
		.topic = topic,
		.expect_rsp_cnt = rsp_cnt,
		.timeout = timeout, //ms
		.payload = payload,
	};

	PayloadBuf* rsp = NULL;
	int ret = mqtt_bus_query(fp, &param, &rsp);
	if(ret == QUERY_RESULT_ERR) {
		MBUS_ERROR("mqtt bus query error\n");
		FREE_PAYLOAD(param.payload);
		return NULL;
	}
	else if (ret == QUERY_RESULT_TIMEOUT) {
		MBUS_ERROR("mqtt bus query timeout\n");
		FREE_PAYLOAD(param.payload);
		return NULL;
	}

#define DEBUG_QUERY
#ifdef DEBUG_QUERY
	MBUS_ERROR("mqtt bus query sueccessful, ret:%d rsp:%s\n", ret, rsp ? "no null" : "null");
	char* str = cJSON_Print(rsp);
	MBUS_ERROR("rsp payload:%s\n", str? str : "null");
	/* free cJSON_Print */
	free(str);
	str = NULL;
#endif

	/* free input cJSON_Parse */
	FREE_PAYLOAD(param.payload);
	return rsp;
}


PayloadBuf* query_simple(struct MBusHandle* fp, const char* topic, PayloadBuf* payload)
{
	return mbus_query(fp, topic, 1, 2000, payload);
}
PayloadBuf* query_no_reply(struct MBusHandle* fp, const char* topic, PayloadBuf* payload)
{
	return mbus_query(fp, topic, 0, 2000, payload);
}

