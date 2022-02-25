#include "first.h"

#include "base.h"
#include "stat_cache.h"
#include "http_kv.h"
#include "fdlog.h"
#include "log.h"
#include "response.h"
#include "http_chunk.h"
#include "http_header.h"

#include "plugin.h"

#include <sys/types.h>
#include "sys-socket.h"
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fdevent.h>

#include <fcntl.h>
#include <signal.h>


#include "cJSON.h"
#include "mod_api/mqtt_bus_query.h"






typedef struct {
	int a;
} plugin_config;



typedef struct {
	PLUGIN_DATA;
	struct MBusHandle* mbud_fp;
} plugin_data;

typedef struct {
	buffer *response;
} handler_ctx;



static cJSON* read_http_json_body(request_st * const r)
{

	if (chunkqueue_is_empty(&r->read_queue)) {
		return NULL;
	}

	unsigned body_len = r->read_queue.bytes_in - r->read_queue.bytes_out;
	if (body_len > 10240) {
		log_error(r->conf.errh, __FILE__, __LINE__, "body too much\n");
		return NULL;
	}

	char* body = calloc(1, body_len);
	if (chunkqueue_read_data(&r->read_queue, body, body_len, r->conf.errh) < 0) {
		log_error(r->conf.errh, __FILE__, __LINE__, "read body failed");
		free(body);
		return NULL;
	}

	log_error(r->conf.errh, __FILE__, __LINE__, "read http body:%s", body);
	cJSON* payload = cJSON_Parse(body);
	free(body);
	return payload;
}

// static handler_ctx * api_handler_ctx_init(void) {
// 	handler_ctx *hctx = calloc(1, sizeof(*hctx));

// 	force_assert(hctx);

// 	hctx->response = chunk_buffer_acquire();
// 	return hctx;
// }


// static void api_handler_ctx_free(handler_ctx *hctx) {

// 	chunk_buffer_release(hctx->response);
// 	free(hctx);
// }

INIT_FUNC(mod_api_init) {
	plugin_data *p;
	//const char *s;
	p = calloc(1, sizeof(*p));
	
	force_assert(p);

	/* todo period check mbus status */
	struct MBusInitAttr attr;
	int timeout = 4;
	memset(&attr, 0, sizeof(attr));

	attr.app_name = "web";
	attr.host = "localhost";
	attr.port = 1883;
	attr.keepalive = 60;
	attr.type = MBUS_TYPE_APP;
	attr.mbus_proto_version = "1.0";
	struct MBusHandle* fp = mqtt_bus_init(&attr);
	if (!fp) {
		MBUS_ERROR ("error, mqtt_bus_init, need reinit at timer\n");
		return p;
	}

	
	while(!mqtt_bus_is_ready(fp) && timeout > 0){
		sleep(1);
		MBUS_ERROR("wait mqtt bus ready...\n");
		timeout--;
	}
	if (timeout == 0) {
		MBUS_ERROR ("error, mqtt connect failed, need reinit at timer\n");
		return p;
	}

	MBUS_ERROR ("successful, mbus connect successful\n");
	p->mbud_fp = fp;

	return p;
}


FREE_FUNC(mod_api_free) {
	//plugin_data *p = p_d;
	(void)p_d;
}


SETDEFAULTS_FUNC(mod_api_set_defaults) {
	(void)p_d;
	(void)srv;
	printf("%s:%d--------defaults---------\n", __FILE__, __LINE__);
	return HANDLER_GO_ON;
}


URIHANDLER_FUNC(mod_api_subrequest_start) {
	(void)p_d;
	//plugin_data *p = p_d;
	//const stat_cache_st *st;
	//data_string *ds;
    log_error(r->conf.errh, __FILE__, __LINE__, "----------subrequest start-------");
	//if (NULL != r->handler_module) return HANDLER_GO_ON;
	return HANDLER_GO_ON;
}


TRIGGER_FUNC(mod_api_trigger)
{
    //const plugin_data * const p = p_d;
    const unix_time64_t cur_ts = log_monotonic_secs;

    printf("%s:%d--------trigger---------\n", __FILE__, __LINE__);
	(void)p_d;
	(void)srv;


    if (cur_ts & 0x7) return HANDLER_GO_ON; /*(continue once each 8 sec)*/

    return HANDLER_GO_ON;
}

static handler_t mod_api_reset(request_st * const r, void *p_d) {

	(void)p_d;

    log_error(r->conf.errh, __FILE__, __LINE__, "--------trigger---------");
    return HANDLER_GO_ON;
}


SUBREQUEST_FUNC(mod_api_subrequest) {
	(void)p_d;
    //plugin_data * const p = p_d;
    //handler_ctx * const hctx = r->plugin_ctx[p->id];
    ///if (NULL == hctx) return HANDLER_GO_ON; /*(should not happen)*/
    log_error(r->conf.errh, __FILE__, __LINE__, "--------subrequest---------");
    handler_t rc = HANDLER_GO_ON;
    return rc;
}


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




static int down_systemBaseInfo(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	(void)m;

	*n = 0;
	if (!http_meta || !http_meta->payload || !mqtt_meta) {
		return -1;
	}

	//cJSON* root = cJSON_Parse (http_meta->payload);
	cJSON* root = http_meta->payload;
	if (!root) {
		return -1;
	}
	
	cJSON* body = cJSON_GetObjectItem(root, "body");
	if (!body) {
		return -1;
	}

	cJSON* op = cJSON_GetObjectItem(body, "operation");
	if (!op) {
		return -1;
	}
	char* op_str = cJSON_GetStringValue(op);
	if (!op_str || strncmp(op_str, "get", strlen("get")+1)) {
		return -1;
	}
	snprintf(mqtt_meta[0].topic, sizeof(mqtt_meta[0].topic),
			"%s%s", "/web", m->m_meta[0].topic);


	FREE_PAYLOAD(http_meta->payload);
	http_meta->payload = NULL;
	mqtt_meta[0].payload = NULL;
	*n = 1;
	return 0;
}



static int up_systemBaseInfo(struct HttpToMqtt* m, struct HttpMeta* http_meta, struct MqttMeta* mqtt_meta, int* n)
{
	(void)m;
	(void)n;
	if (!http_meta || !mqtt_meta || !n) {
		return -1;
	}

	//cJSON* root = cJSON_Parse (http_meta->payload);
	cJSON* root = mqtt_meta[0].payload;
	if (!root) {
		return -1;
	}
	char* str  = cJSON_Print(root);
	if (str) {
		fprintf(stderr, "up root:%s\n", str);
	}
	
	cJSON* body = cJSON_GetObjectItem(root, "body");
	if (!body) {
		FREE_PAYLOAD(mqtt_meta[0].payload);
		return -1;
	}

	cJSON_DeleteItemFromObject(body, "electronicTag");
	cJSON_DeleteItemFromObject(body, "rebootTime");
	cJSON_DeleteItemFromObject(root, "token");

	http_meta->payload = root;
	return 0;
}


int local_info_token(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr)
{
	(void)ptr;
	(void)m;
	/* todo check payload */

	// todo get info from database with name

	cJSON *root, *body;
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "statusCode", 200);
	cJSON_AddStringToObject(root, "statusDesc", "OK");

	body = cJSON_CreateObject();
	cJSON_AddStringToObject(body, "username", "ypp");
	cJSON_AddStringToObject(body, "description", "man");

    const char *strings[1] ={ "admin"};
	cJSON_AddItemToObject(body, "roles", cJSON_CreateStringArray(strings, 1));

	cJSON_AddItemToObject(root, "body", body);
	http_meta->payload = root;
	return 0;
}



int local_updatePw(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr)
{
	(void)ptr;
	(void)m;
	/* todo check payload */

	// todo get info from database with name

	cJSON *root, *body;
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "statusCode", 200);
	cJSON_AddStringToObject(root, "statusDesc", "OK");
	cJSON_AddStringToObject(root, "timestamp", "2021-11-02 18:00:00");
	http_meta->payload = root;
	return 0;
}


int local_info_list(struct HttpLocal* m, struct HttpMeta* http_meta, void* ptr)
{
	(void)ptr;
	(void)m;
	/* todo check payload */

	// todo get info from database with name

	cJSON *root, *body, *arr, *tmp;
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "statusCode", 200);
	cJSON_AddStringToObject(root, "statusDesc", "OK");
	cJSON_AddStringToObject(root, "timestamp", "2021-11-02 18:00:00");

	arr = cJSON_CreateArray();

	tmp = cJSON_CreateObject();
	cJSON_AddStringToObject(tmp, "username", "admin");
	cJSON_AddNumberToObject(tmp, "userId", 1);
	cJSON_AddStringToObject(tmp, "userType", "admin");
	cJSON_AddItemToArray(arr, tmp);

	tmp = cJSON_CreateObject();
	cJSON_AddStringToObject(tmp, "username", "user");
	cJSON_AddNumberToObject(tmp, "userId", 2);
	cJSON_AddStringToObject(tmp, "userType", "operator");
	cJSON_AddItemToArray(arr, tmp);
	

	body = cJSON_CreateObject();
	cJSON_AddItemToObject(body, "list", arr);
	cJSON_AddNumberToObject(body, "number", 2);

	cJSON_AddItemToObject(root, "body", body);

	http_meta->payload = root;
	return 0;
}


static struct HttpLocal m_user[] = {
	{
		.h_meta = {.uri = "info/token", .role = 1,},
		.local_handler = local_info_token,
	},
	{
		.h_meta = {.uri = "updatePw", .role = 1,},
		.local_handler = local_updatePw,
	},
	{
		.h_meta = {.uri = "info/list", .role = 1,},
		.local_handler = local_info_list,
	},
	
};

static struct HttpToMqtt m_system[] = {
	{
		.h_meta = {.uri = "systemBaseInfo", .role = 1,},
		.m_meta = {{.topic = "/get/request/rasdk/deviceInfo",}},
		.down_switch_func = down_systemBaseInfo,
		.up_switch_func = up_systemBaseInfo,
	}
};


static struct ModuleAdapter adapter[] = {
	{
		.id = 1,
		.root_uri = "/api/user/",
		.n = 3,
		.local = m_user,
	},
	{
		.id = 2,
		.root_uri = "/api/system/",
		.n = 1,
		.proxy = m_system,
	},

};
#define MSZIE (int)(sizeof(adapter) / sizeof(adapter[0]))


static int get_env_username_role(request_st *r, buffer **username, unsigned* role)
{
	*role = 0;
	*username = NULL;

	buffer *us, *ro;
    us = http_header_env_get(r, CONST_STR_LEN("username"));
	if (!us || !us->ptr) return -1;
	*username = us;

    ro = http_header_env_get(r, CONST_STR_LEN("role"));
	if (!ro || !ro->ptr) return -1;

	char *endptr;
	*role = strtol(ro->ptr, &endptr, 16);
	if (ro->ptr == endptr) {
		return -1;
	}
	return 0;
}

URIHANDLER_FUNC(mod_api_uri_handler) {
    plugin_data *p = p_d;
	int index, ret, i;

	log_error(r->conf.errh, __FILE__, __LINE__, "--------1uri:%s---------", r->uri.path.ptr);
	if(!r->uri.path.ptr) {
		r->http_status = 401;
		r->resp_body_finished = 1;
		return HANDLER_FINISHED;
	}
	
	/* find the mode */
	char* uri = r->uri.path.ptr;
	for (i = 0; i < MSZIE; i++) {
		if (!strncmp(uri, adapter[i].root_uri, strlen(adapter[i].root_uri))) {
			break;
		}
	}
	if (i == MSZIE) {
		r->http_status = 404;
		r->resp_body_finished = 1;
		log_error(r->conf.errh, __FILE__, __LINE__, "not find the module\n");
		return HANDLER_FINISHED;
	}
	index = i;
	uri += strlen(adapter[i].root_uri);



	struct HttpMeta http_meta;
	http_meta.payload = read_http_json_body(r);
	// if (get_env_username_role(r, &http_meta.username, &http_meta.role)) {
	// 	r->http_status = 401;
	// 	r->resp_body_finished = 1;
	// 	log_error(r->conf.errh, __FILE__, __LINE__, "not find the username and role\n");
	// 	return HANDLER_FINISHED;
	// }

	if (adapter[index].local) {
		struct HttpLocal* local = adapter[index].local;
		for (i = 0; i < adapter[index].n; i++) {
			if (!strncmp(uri, local[i].h_meta.uri, strlen(local[i].h_meta.uri) + 1)) {
				break;
			}
		}
		local = local + i;

		if (i == adapter[index].n) {
			r->http_status = 404;
			r->resp_body_finished = 1;
			log_error(r->conf.errh, __FILE__, __LINE__, "not find the uri\n");
			return HANDLER_FINISHED;
		}

		/* no access right to call the api */
		// if (!(local->h_meta.role & http_meta.role)) {
		// 	r->http_status = 404;
		// 	r->resp_body_finished = 1;
		// 	log_error(r->conf.errh, __FILE__, __LINE__, "no access right to call uri\n");
		// 	return HANDLER_FINISHED;
		// }

		ret = local->local_handler(local, &http_meta, NULL);
		if (http_meta.payload) {
			char* str = cJSON_Print(http_meta.payload);
			if (str) {
				http_chunk_append_mem(r, str, strlen(str));
				free(str);
			}
			FREE_PAYLOAD(http_meta.payload);
		}
		else {
			log_error(r->conf.errh, __FILE__, __LINE__, "no http payload\n");
		}

		r->http_status = 200;
		r->resp_body_finished = 1;
		return HANDLER_FINISHED;
	}
	
	if (adapter[index].proxy) {

		/* find secondary uri handler */
		struct HttpToMqtt* proxy = adapter[index].proxy;
		for (i = 0; i < adapter[index].n; i++) {
			if (!strncmp(uri, proxy[i].h_meta.uri, strlen(proxy[i].h_meta.uri) + 1)) {
				break;
			}
		}
		proxy = proxy + i;


		/* not find */
		if (i == adapter[index].n) {
			r->http_status = 404;
			r->resp_body_finished = 1;
			log_error(r->conf.errh, __FILE__, __LINE__, "not req find the uri\n");
			return HANDLER_FINISHED;
		}

		/* no access right to call the api */
		// if (!(proxy->h_meta.role & http_meta.role)) {
		// 	r->http_status = 404;
		// 	r->resp_body_finished = 1;
		// 	log_error(r->conf.errh, __FILE__, __LINE__, "no access right to call uri\n");
		// 	return HANDLER_FINISHED;
		// }

		struct MqttMeta mmeta[4];
		memcpy(mmeta, proxy->m_meta, sizeof(mmeta));
		int topic_num = 4;

		ret = proxy->down_switch_func(proxy, &http_meta, &mmeta[0], &topic_num);
		log_error(r->conf.errh, __FILE__, __LINE__, "down switch func return:%d\n", ret);

		for (i = 0; i < topic_num; i++) {
			// todo query( topic and payload)
			// connect response
			if(p->mbud_fp) {
				// PayloadBuf* rsp = query_simple(p->mbud_fp, 
				// 		"/web/set/request/rasdk/deviceInfo", NULL);
				PayloadBuf* rsp = query_simple(p->mbud_fp, mmeta[i].topic, mmeta[i].payload);
				FREE_PAYLOAD(mmeta[i].payload);
				if (!rsp) {
					log_error(r->conf.errh, __FILE__, __LINE__, "query error :%s\n",  mmeta[i].topic);
				}
				else {
					mmeta[i].payload = rsp;
				}
			}
		}
		ret = proxy->up_switch_func(proxy, &http_meta, &mmeta[0], &topic_num);
		log_error(r->conf.errh, __FILE__, __LINE__, "up switch func return:%d\n", ret);
		if (http_meta.payload) {
			char* str = cJSON_Print(http_meta.payload);
			if (str) {
				http_chunk_append_mem(r, str, strlen(str));
				free(str);
			}
			FREE_PAYLOAD(http_meta.payload);
		}
		else {
			log_error(r->conf.errh, __FILE__, __LINE__, "no rsp http payload\n");
		}

		r->http_status = 200;
		r->resp_body_finished = 1;
		return HANDLER_FINISHED;
	}

	log_error(r->conf.errh, __FILE__, __LINE__, "no handler goon\n");

	return HANDLER_GO_ON;
}


int mod_api_plugin_init(plugin *p);
int mod_api_plugin_init(plugin *p) {
	p->version     = LIGHTTPD_VERSION_ID;
	p->name        = "api";

	p->handle_uri_clean = mod_api_uri_handler;
	p->handle_request_reset = mod_api_reset;
	p->handle_subrequest_start = mod_api_subrequest_start;
	p->handle_subrequest = mod_api_subrequest;
	p->handle_trigger = mod_api_trigger;
	p->init           = mod_api_init;
	p->cleanup        = mod_api_free;
	p->set_defaults   = mod_api_set_defaults;

    printf("%s:%d--------plugin init---------\n", __FILE__, __LINE__);
	return 0;
}
