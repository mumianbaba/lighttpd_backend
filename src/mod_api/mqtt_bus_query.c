#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "mod_api/mqtt_bus_query.h"




PayloadBuf* mbus_query(struct MBusHandle* fp, const char* topic, int rsp_cnt,  int timeout, PayloadBuf* payload)
{
	if (!fp || !topic) {
		return NULL;
	}

	int ret = -1;
	struct MBusQueryParam param;
	memset(&param, 0, sizeof(param));

	param.topic = (char*)topic;
	param.expect_rsp_cnt = rsp_cnt;
	param.timeout = timeout; //30s
	param.payload = payload;
	param.flag.payload_type = MBUS_PAYLOAD_CJSON;
	param.flag.proto_type = MBUS_PROTO_RASDK;

	struct MBusRead* readd = NULL;
	ret = mqtt_bus_query(fp, &param, &readd);
	if(ret == QUERY_RESULT_OK) {
		ret = 0;
	}
	else if (ret == QUERY_RESULT_TIMEOUT) {
		fprintf(stderr, "%s:%d mqtt bus query timeout\n", __func__, __LINE__);
		ret = -1;
	}
	else if (ret == QUERY_RESULT_ERR){
		fprintf(stderr, "%s:%d mqtt bus query error\n", __func__, __LINE__);
		ret = -1;
	}
	else {
		fprintf(stderr, "%s:%d mqtt bus query error:%d\n", __func__, __LINE__, ret);
		ret = -1;
	}
	if (ret) return NULL;
	fprintf(stderr, "mqtt bus query sueccessful, ret:%d data:%p  data->payload:%p type:%d\n",
					ret, (void*)readd, readd->payload, readd->flag.payload_type);

	PayloadBuf* rsp = readd->payload;
	readd->payload = NULL;
	mqtt_bus_free_MBusRead(readd, 1);


#define DEBUG_QUERY
#ifdef DEBUG_QUERY
	char* str = cJSON_Print(rsp);
	fprintf(stderr, "rsp payload:%s\n", str? str : "null");
	/* free cJSON_Print */
	free(str);
	str = NULL;
#endif

	if (!rsp) {
		fprintf (stderr, "%s ----careful---check logic ---------\n", __func__);
	}
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

