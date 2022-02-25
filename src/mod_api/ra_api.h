#ifndef RA_API_H
#define RA_API_H
#include "first.h"
#include "buffer.h"

#include "cJSON.h"


#include "mqtt_bus/mbus_api.h"
#include "mqtt_bus/mbus_log.h"


struct HttpMeta {
	char* uri;
	PayloadBuf* payload;
	buffer* username;
	unsigned   role;
};
struct MqttMeta {
	char topic[128];
	PayloadBuf* payload;
};
struct HttpToMqtt;
struct HttpLocal;

typedef int (*http_and_mqtt_switch)(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n);

typedef int (*http_local_handler)(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr);


struct HttpToMqtt {
	struct HttpMeta h_meta;
	struct MqttMeta m_meta[4];
	http_and_mqtt_switch down_switch_func;
	http_and_mqtt_switch up_switch_func;
};

struct HttpLocal {
	struct HttpMeta h_meta;
	http_local_handler local_handler;
};

struct ModuleAdapter {
	int id;
	char* root_uri;
	int n;
	struct HttpToMqtt* proxy;
	struct HttpLocal* local;
};


int adapter_find_request(buffer* uri, void** ptr);
void clean_http_meta(struct HttpMeta* meta, int n);
void clean_mqtt_meta(struct MqttMeta* meta, int n);


int down_systemBaseInfo(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n);
int up_systemBaseInfo(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n);
int local_info_token(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr);
int local_updatePw(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr);
int local_info_list(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr);



#define JSON_GET_OP()  \
cJSON* root = http_meta->payload;\
if (!root) {\
	goto error;\
}\
cJSON* body = cJSON_GetObjectItem(root, "body");\
if (!body) {\
	goto error;\
}\
cJSON* op = cJSON_GetObjectItem(body, "operation");\
if (!op) {\
	goto error;\
}\
char* op_str = cJSON_GetStringValue(op);\
if (!op_str) {\
	goto error;\
}


#define JSON_GET_BODY(a)  \
cJSON* root = a->payload;\
if (!root) {\
	goto error;\
}\
cJSON* body = cJSON_GetObjectItem(root, "body");\
if (!body) {\
	goto error;\
}


#define JSON_ADD_RESULT(code, desc)  \
	cJSON_AddNumberToObject(root, "statusCode", code);\
	cJSON_AddStringToObject(root, "statusDesc", desc);


#define JSON_DEBUG_ROOT() \
	do {\
		char* str  = cJSON_Print(root);\
		if (str) {\
			fprintf(stderr, "up root:%s\n", str);\
			free(str);\
			str = NULL;\
		}\
	}while(0)




#define JSON_OP_IS(a)      (0 == strncmp(op_str, a, 8))
#define JSON_OP_NOT_IS(a)  strncmp(op_str, a, 8)
#define JSON_BODY_DEL(a)   cJSON_DeleteItemFromObject(body, a)
#define JSON_BODY_ADD_STR(a, b)   cJSON_AddStringToObject(body, a, b)
#define JSON_BODY_ADD_NUM(a, b)   cJSON_AddNumberToObject(body, a, b)


#define JSON_ROOT_DEL(a)   cJSON_DeleteItemFromObject(root, a)
#define JSON_ROOT_ADD_STR(a, b)   cJSON_AddStringToObject(root, a, b)
#define JSON_ROOT_ADD_NUM(a, b)   cJSON_AddNumberToObject(root, a, b)


#define JOINT_TOPIC(a, n, c) snprintf(a, n, "%s%s", "/web", c)


#endif




