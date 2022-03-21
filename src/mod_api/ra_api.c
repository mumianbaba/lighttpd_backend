#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#include "mod_api/mqtt_bus_query.h"
#include "mod_api/ra_api.h"
#include "mod_api/ra_data.h"

#define PRINT_ERR(fmt, ...)  fprintf(stderr, fmt, ##__VA_ARGS__)


void adapter_test_init(void)
{
	struct HttpToMqtt* proxy = NULL;
	struct HttpLocal* local = NULL;

	int i, j, n;
	for (i = 0; i < MSZIE; i++) {
		n = adapter[i].n;
		if (adapter[i].local) {
			local = adapter[i].local;

			for (j = 0; j < n; j++) {
				if (local[j].test[0]) {
					local[j].conf = cJSON_Parse(local[j].test[0]);
				}
			}
		}
		else {
			proxy = adapter[i].proxy;
			for (j = 0; j < n; j++) {
				if (proxy[j].test[0]) {
					proxy[j].conf = cJSON_Parse(proxy[j].test[0]);
				}
			}
		}
	}
	return;
}


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

	//*n = 0;
	JSON_GET_OP();
	
	if (JSON_OP_NOT_IS("get")) {
		goto error;
	}
	JOINT_GET_TOPIC(mqtt_meta[0].topic, sizeof(mqtt_meta[0].topic), m->m_meta[0].topic);

	/* end the http meta payload cjson mem life */
	clean_http_meta(http_meta, 1);
	mqtt_meta[0].payload = NULL;
	//*n = 1;
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
	(void)m;
	// JSON_GET_OP();
	// if (JSON_OP_NOT_IS("get")) {
	// 	goto error;
	// }
	// JSON_BODY_DEL("operation");
	// JSON_BODY_DEL("timestamp");
	cJSON* root = cJSON_CreateObject();
	cJSON* body = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "body", body);

	JSON_ADD_RESULT(200, "OK");
	JSON_BODY_ADD_STR("username", http_meta->username->ptr);
	JSON_BODY_ADD_STR("description", 
						(http_meta->role == 0x3) ? "a administrator": "a normal user");
	JSON_BODY_ADD_STR("role",
						(http_meta->role == 0x3) ? "admin": "operator");
	http_meta->payload = root;
	return 0;
/* error:
	fprintf(stderr, "local %s error\n", m->h_meta.uri);
	clean_http_meta(http_meta, 1);
	return -1; */
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




/* all down swich func clean the http_meta payload */
static int down_common_get(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	if (!http_meta || !http_meta->payload || !mqtt_meta || !n) {
		//clean_http_meta(http_meta, 1);
		return -1;
	}

	JOINT_GET_TOPIC(mqtt_meta[0].topic, sizeof(mqtt_meta[0].topic), m->m_meta[0].topic);
	mqtt_meta[0].payload = NULL;
	return 0;
}



/* all down swich func clean the http_meta payload */
static int down_common_set(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	if (!http_meta || !http_meta->payload || !mqtt_meta || !n) {
		clean_http_meta(http_meta, 1);
		return -1;
	}
	JSON_GET_BODY(http_meta);

	int i, j;

	for (i = 0; i < *n; i++) {
		JOINT_SET_TOPIC(mqtt_meta[i].topic, sizeof(mqtt_meta[i].topic), m->m_meta[i].topic);
		struct KeyPair* kp =  mqtt_meta[i].pair.list;
		if (!kp) {
			return 0;
		}
	
		cJSON* new_obj;
		cJSON* new_root = cJSON_CreateObject();
		cJSON* new_body = cJSON_CreateObject();
	
		for (j = 0; j < mqtt_meta[i].pair.n; j++) {
			if (!(new_obj = cJSON_GetObjectItem(body, kp[j].key1))) {
				PRINT_ERR ("no find the key:%s at request\n", kp[j].key1);
				return -1;
			}
			cJSON_AddItemToObject(new_body, kp[j].key2, cJSON_Duplicate(new_obj, 0));
		}
		cJSON_AddItemToObject(new_root, "body", new_body);
		mqtt_meta[i].payload = new_root;
	}	

	/* end the http meta payload cjson mem life */
	//clean_http_meta(http_meta, 1);
	return 0;

error:
	fprintf(stderr, "down %s error\n", m->h_meta.uri);
	//clean_http_meta(http_meta, 1);
	return -1;
}



static int get_response_is_successful(struct MqttMeta* mqtt_meta, int idx, cJSON** simple)
{
	int i;
	if (!mqtt_meta) {
		PRINT_ERR("%s param null\n", __func__);
		return 0;
	}

	cJSON* new_obj;
	for (i = 0; i < idx; i++) {
		if (!mqtt_meta[i].payload) {
			PRINT_ERR("%s payload null\n", __func__);
			return 0;
		}
		if (!(new_obj = cJSON_GetObjectItem(mqtt_meta[0].payload, "statusCode"))) {
			PRINT_ERR ("no find the key:%s at request\n", "statusCode");
			return 0;
		}
		if (cJSON_GetNumberValue(new_obj) != 200) {
			if(simple) {
				*simple = mqtt_meta[i].payload;
				mqtt_meta[i].payload = NULL;
			}
			return 0;
		}
	}
	return 1;
}



static int set_response_is_successful(struct MqttMeta* mqtt_meta, int idx, cJSON** simple)
{
	int i;
	if (!mqtt_meta) {
		PRINT_ERR("%s param null\n", __func__);
		return 0;
	}

	cJSON* new_obj;
	for (i = 0; i < idx; i++) {
		if (!mqtt_meta[i].payload) {
			PRINT_ERR("%s payload null\n", __func__);
			return 0;
		}
		if (!(new_obj = cJSON_GetObjectItem(mqtt_meta[0].payload, "statusCode"))) {
			PRINT_ERR ("no find the key:%s at request\n", "statusCode");
			return 0;
		}
		if (cJSON_GetNumberValue(new_obj) != 200) {
			if(simple) {
				*simple = mqtt_meta[i].payload;
				mqtt_meta[i].payload = NULL;
			}
			return 0;
		}
	}
	if(simple) {
		*simple = mqtt_meta[0].payload;
		mqtt_meta[0].payload = NULL;
	}
	return 1;
}
static int up_common_set(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	(void)m;
	int idx = *n;
	cJSON* rsp_json = NULL;
	int ok = 0;
	ok = set_response_is_successful(mqtt_meta, idx, &rsp_json);
	if (rsp_json) {
		http_meta->payload = rsp_json;
		return 0;
	}
	
	PRINT_ERR("%s xxxxxxxxxx-need--logic--check---careful+1\n", __func__);
	if (!ok) {
		cJSON* root = cJSON_CreateObject();
		cJSON_AddNumberToObject(root, "statusCode", 400);
		http_meta->payload = root;
		return 0;
	}
	
	PRINT_ERR("%s xxxxxxxxxx-need--logic--check---careful+2\n", __func__);
	return 0;
}


static int up_common_get(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	(void)m;

	int idx = *n;
	cJSON* rsp_json =NULL;
	int ok = get_response_is_successful(mqtt_meta, idx, &rsp_json);
	if (!ok && rsp_json) {
		/* failed, no need more handle */
		http_meta->payload = rsp_json;
		return 0;
	}

	if (!ok) {
		cJSON* root = cJSON_CreateObject();
		cJSON_AddNumberToObject(root, "statusCode", 400);
		http_meta->payload = root;
		return 0;
	}

	cJSON* new_root = cJSON_CreateObject();
	cJSON* new_body = cJSON_CreateObject();
	cJSON* new_obj;
	cJSON_AddItemToObject(new_root, "body", new_body);

	int i, j;
	for (i = 0; i < idx; i++) {
		cJSON* body = cJSON_GetObjectItem(mqtt_meta[i].payload, "body");
		struct KeyPair* kp =  mqtt_meta[i].pair.list;
		if (!kp) {
			return 0;
		}

		for (j = 0; j < mqtt_meta[i].pair.n; j++) {
			if (!(new_obj = cJSON_GetObjectItem(body, kp[j].key2))) {
				PRINT_ERR ("get request no find the key:%s at request\n", kp[j].key2);
				cJSON_Delete(new_root);
				return -1;
			}
			cJSON_DetachItemViaPointer(body, new_obj);
			//PRINT_ERR("kp[%d].key1:%s\n", j, kp[j].key1);
			cJSON_AddItemToObject(new_body, kp[j].key1, new_obj);
		}
	}

	http_meta->payload = new_root;
	cJSON_AddNumberToObject(new_root, "statusCode", 200);
	return 0;
}




int down_common_handle(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	if (!m || !http_meta || !mqtt_meta) {
		PRINT_ERR("%s param null\n", __func__);
		return -1;
	}

	int ret = -1;
	if(http_meta->flag & REQ_FLAG_GET) {
		ret = down_common_get(m, http_meta, mqtt_meta, n);
	}
	else if (http_meta->flag & REQ_FLAG_SET){
		ret = down_common_set(m, http_meta, mqtt_meta, n);
	}
	else {
		return -1;
	}
	return ret;
}


int up_common_handle(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	if (!m || !http_meta || !mqtt_meta) {
		PRINT_ERR("%s param null\n", __func__);
		return -1;
	}
	
	int ret = -1;
	if(http_meta->flag & REQ_FLAG_GET) {
		ret = up_common_get(m, http_meta, mqtt_meta, n);
	}
	else if (http_meta->flag & REQ_FLAG_SET){
		ret = up_common_set(m, http_meta, mqtt_meta, n);
	}
	else {
		return -1;
	}
	return ret;
}
