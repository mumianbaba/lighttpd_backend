#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "mod_api/mqtt_bus_query.h"
#include "mod_api/ra_api.h"
#include "mod_api/ra_data.h"


int adapter_find_request(buffer* uri, void** ptr){

	int ret = -1, i;
	*ptr = NULL;

	struct ModuleAdapter* ad = NULL;
	for (i = 0; i < MSZIE; i++) {
		if (!strncmp(uri->ptr, adapter[i].root_uri, strlen(adapter[i].root_uri))) {
			ad = &adapter[i];
			break;
		}
	}

	if (!ad) goto error;
	if (!ad->local && !ad->proxy) goto error;

	char* sub = uri->ptr + strlen(adapter[i].root_uri);
	if (ad->local) {
		struct HttpLocal* local = ad->local;
		for (i = 0; i < ad->n; i++) {
			if (!strncmp(sub, local[i].h_meta.uri, strlen(local[i].h_meta.uri) + 1)) {
				*ptr = &local[i];
				ret = 0;
				return ret;
			}
		}
		fprintf(stderr, "no find the request:%s\n", uri->ptr);
	}

	if (ad->proxy) {
		struct HttpToMqtt* proxy = ad->proxy;
		for (i = 0; i < ad->n; i++) {
			if (!strncmp(sub, proxy[i].h_meta.uri, strlen(proxy[i].h_meta.uri) + 1)) {
				*ptr = &proxy[i];
				ret = 1;
				return ret;
			}
		}
		fprintf(stderr, "no find the request:%s\n", uri->ptr);
	}

	return ret;
error:
	fprintf(stderr, "no find the request mode:%s\n", uri->ptr);
	return -1;
}


void clean_http_meta(struct HttpMeta* meta, int n)
{
	if (!meta) {
		return;
	}

	int i;
	for (i = 0; i < n; i++) {
		FREE_PAYLOAD(meta[i].payload);
	}
}


void clean_mqtt_meta(struct MqttMeta* meta, int n)
{
	if (!meta) {
		return;
	}

	int i;
	for (i = 0; i < n; i++) {
		FREE_PAYLOAD(meta[i].payload);
	}
}


/* all down swich func clean the http_meta payload */
int down_systemBaseInfo(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	if (!http_meta || !http_meta->payload || !mqtt_meta || !n) {
		clean_http_meta(http_meta, 1);
		return -1;
	}

	*n = 0;
	JSON_GET_OP();
	
	if (JSON_OP_NOT_IS("get")) {
		goto error;
	}
	JOINT_TOPIC(mqtt_meta[0].topic, sizeof(mqtt_meta[0].topic), m->m_meta[0].topic);

	/* end the http meta payload cjson mem life */
	clean_http_meta(http_meta, 1);
	mqtt_meta[0].payload = NULL;
	*n = 1;
	return 0;

error:
	fprintf(stderr, "down %s error\n", m->h_meta.uri);
	clean_http_meta(http_meta, 1);
	return -1;
}


/* http_meta is cleanly, all up swich func clean the mqtt_meta payload */
int up_systemBaseInfo(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	(void)m;
	if (!http_meta || !mqtt_meta || !n || *n != 1) {
		clean_mqtt_meta(mqtt_meta, 1);
		return -1;
	}

	JSON_GET_BODY(mqtt_meta);
	JSON_BODY_DEL("electronicTag");
	JSON_BODY_DEL("rebootTime");
	JSON_ROOT_DEL("token");

	http_meta->payload = root;
	JSON_DEBUG_ROOT();
	return 0;

error:
	fprintf(stderr, "up %s error\n", m->h_meta.uri);
	clean_mqtt_meta(mqtt_meta, 1);
	return -1;
}


int local_info_token(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr)
{
	(void)ptr;
	JSON_GET_OP();
	if (JSON_OP_NOT_IS("get")) {
		goto error;
	}
	JSON_BODY_DEL("operation");
	JSON_BODY_DEL("timestamp");

	JSON_ADD_RESULT(200, "OK");
	JSON_BODY_ADD_STR("username", http_meta->username->ptr);
	JSON_BODY_ADD_STR("description", 
						(http_meta->role == 0x3) ? "a administrator": "a normal user");
	JSON_BODY_ADD_STR("role",
						(http_meta->role == 0x3) ? "admin": "operator");
	http_meta->payload = root;
	return 0;
error:
	fprintf(stderr, "local %s error\n", m->h_meta.uri);
	clean_http_meta(http_meta, 1);
	return -1;
}



int local_updatePw(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr)
{
	(void)ptr;
	JSON_GET_OP();
	if (JSON_OP_NOT_IS("set")) {
		goto error;
	}

	// todo check the want to change username role and decrypt compare


	JSON_BODY_DEL("operation");
	JSON_BODY_DEL("timestamp");

	JSON_ADD_RESULT(200, "OK");
	http_meta->payload = root;
	return 0;
error:
	fprintf(stderr, "local %s error\n", m->h_meta.uri);
	clean_http_meta(http_meta, 1);
	return -1;
}


int local_info_list(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr)
{
	(void)ptr;
	JSON_GET_OP();
	if (JSON_OP_NOT_IS("get")) {
		goto error;
	}
	JSON_BODY_DEL("operation");
	JSON_BODY_DEL("timestamp");

	JSON_ADD_RESULT(200, "OK");
	JSON_BODY_ADD_NUM("number", 2);


	// todo get info from database with name

	cJSON* arr = cJSON_CreateArray();
	cJSON* tmp = cJSON_CreateObject();
	cJSON_AddStringToObject(tmp, "username", "admin");
	cJSON_AddNumberToObject(tmp, "userId", 1);
	cJSON_AddStringToObject(tmp, "role", "admin");
	cJSON_AddItemToArray(arr, tmp);

	tmp = cJSON_CreateObject();
	cJSON_AddStringToObject(tmp, "username", "user");
	cJSON_AddNumberToObject(tmp, "userId", 2);
	cJSON_AddStringToObject(tmp, "role", "operator");
	cJSON_AddItemToArray(arr, tmp);

	cJSON_AddItemToObject(body, "list", arr);
	http_meta->payload = root;
	return 0;
error:
	fprintf(stderr, "local %s error\n", m->h_meta.uri);
	clean_http_meta(http_meta, 1);
	return -1;
}
