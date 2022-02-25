#ifndef MQTT_BUS_QUERY_H
#define MQTT_BUS_QUERY_H
#include "first.h"

#include "cJSON.h"


#include "mqtt_bus/mbus_api.h"
#include "mqtt_bus/mbus_log.h"


typedef cJSON  PayloadBuf;

#define FREE_PAYLOAD(a)  if (a) {cJSON_Delete(a); a = NULL;}


PayloadBuf* mbus_query(struct MBusHandle* fp, const char* topic, int rsp_cnt,  int timeout, PayloadBuf* playload);
PayloadBuf* query_simple(struct MBusHandle* fp, const char* topic, PayloadBuf* playload);
PayloadBuf* query_no_reply(struct MBusHandle* fp, const char* topic, PayloadBuf* playload);

#endif




