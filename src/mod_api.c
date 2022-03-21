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
#include "mod_api/ra_api.h"
#define PRINT_ERR(fmt, ...)  fprintf(stderr, fmt, ##__VA_ARGS__)


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

	char* body = calloc(1, body_len + 1);
	if (chunkqueue_read_data(&r->read_queue, body, body_len, r->conf.errh) < 0) {
		log_error(r->conf.errh, __FILE__, __LINE__, "read body failed");
		free(body);
		return NULL;
	}

	log_error(r->conf.errh, __FILE__, __LINE__, "read http body:%s", body);
	cJSON* payload = cJSON_ParseWithLength(body, body_len + 1);
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

	adapter_test_init();
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

static int get_env_username_role(request_st *r, buffer **username, unsigned* role)
{
#if 1
	(void)r;
	*username = buffer_init();
	buffer_copy_string(*username, "linuxing");
	*role = 0x1;
	return 0;
#else
	*role = 0;
	*username = NULL;

	buffer *us, *ro;
    us = http_header_env_get(r, CONST_STR_LEN("username"));
	if (!us || !us->ptr) goto error;
	*username = us;

    ro = http_header_env_get(r, CONST_STR_LEN("role"));
	if (!ro || !ro->ptr) goto error;

	char *endptr;
	*role = strtol(ro->ptr, &endptr, 16);
	if (ro->ptr == endptr) {
		goto error;
	}
	return 0;

error:
	log_error(r->conf.errh, __FILE__, __LINE__, "get username role error\n");
	return -1;
#endif
}

static inline int api_access_right_check(struct HttpMeta* meta, unsigned role)
{
	int ret = (meta->role & role) ? 1 : 0;
	if (ret == 0) {
		fprintf(stderr, "no access_right %s\n", meta->uri);
	}
	return ret;
}


static int fill_http_meta(request_st *r, struct HttpMeta* meta)
{
	if (get_env_username_role(r, &meta->username, &meta->role)) {
		return -1;
	}

	meta->payload = read_http_json_body(r);
	return 0;
}

static  char* api_sample_response(int code, char* desc)
{
	cJSON* root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "statusCode", code);
	if (desc) {
		cJSON_AddStringToObject(root, "statusDesc", desc);
	}

	cJSON_AddStringToObject(root, "timestamp", "2021-11-02 18:00:00");
	return cJSON_Print(root);
}


static int test_fake_bankend(void *handle, struct HttpMeta* http_meta, int type)
{
	// local handle
	if (type == 0) {
		struct HttpLocal* h = handle;
		if (h->test[0] && http_meta->flag & REQ_FLAG_GET) {
			return cJSON_Print(h->conf);
		}
		if (h->test[1] && http_meta->flag & REQ_FLAG_SET) {
			h->conf = http_meta->payload;
			cJSON* body = cJSON_GetObjectItem(http_meta->payload, "body");
			cJSON_DeleteItemFromObject(body, "operation")
			return strdup(h->test[1]);
		}
	}
	else {
		struct HttpToMqtt* h = handle;
		if (h->test[0] && http_meta->flag & REQ_FLAG_GET) {
			return cJSON_Print(h->conf);
		}
		if (h->test[1] && http_meta->flag & REQ_FLAG_SET) {
			h->conf = http_meta->payload;
			return strdup(h->test[1]);
		}
	}
	return NULL;
}

static char* local_request_handle(struct HttpLocal* handle, struct HttpMeta* http_meta, void* ptr)
{
	(void) ptr;
	if (!handle || !http_meta) goto error;

	if(!api_access_right_check(&handle->h_meta, http_meta->role)) {
		goto error;
	}

	JSON_GET_OP();
	if (JSON_OP_IS("get")) {
		http_meta->flag |= REQ_FLAG_GET;
	}
	else if (JSON_OP_IS("set") || JSON_OP_IS("update")) {
		http_meta->flag |= REQ_FLAG_SET;
	}



	int ret = handle->local_handler(handle, http_meta, NULL);
	if (ret != 0 || !http_meta->payload) {
		goto error;
	}

	char* string = cJSON_Print(http_meta->payload);
	FREE_PAYLOAD(http_meta->payload);
	return string;
error:
	return api_sample_response(500, "Failed");
}




static inline int get_mqtt_meta_num(struct MqttMeta* meta, int max)
{
	int i;
	for(i = 0; i < max; i++) {
		if(!meta[i].topic || meta[i].topic[0] == '\0') {
			break;
		}
	}
	return i;
}


static char* proxy_request_handle(struct HttpToMqtt* handle, struct HttpMeta* http_meta, void* ptr)
{
	if (!handle || !http_meta || !ptr) {
		return api_sample_response(501, "Failed");
	};

	if(!api_access_right_check(&handle->h_meta, http_meta->role)) {
		return api_sample_response(400, "Failed");
	}

	// get request type
	{
		JSON_GET_OP();
		if (JSON_OP_IS("get")) {
			http_meta->flag |= REQ_FLAG_GET;
		}
		else if (JSON_OP_IS("set") || JSON_OP_IS("update")) {
			http_meta->flag |= REQ_FLAG_SET;
		}	
	}

	// test for frontend
	PRINT_ERR ("test[0]:%p test[1]:%p http_meta->flag:%x\n", handle->test[0], handle->test[1], http_meta->flag);
	if (handle->test[0] && http_meta->flag & REQ_FLAG_GET) {
		return cJSON_Print(handle->conf);
	}
	if (handle->test[1] && http_meta->flag & REQ_FLAG_SET) {
		handle->conf = http_meta->payload;
		return strdup(handle->test[1]);
	}


	plugin_data *p = ptr;
	/* downstream switch */
	struct MqttMeta mmeta[8];
	memcpy(mmeta, handle->m_meta, sizeof(mmeta));
	int topic_num = 
		get_mqtt_meta_num(mmeta, sizeof(mmeta) / sizeof(mmeta[0]));

	fprintf (stderr, "the mqtt http_meta num:%d\n", topic_num);
	int ret = handle->down_switch_func(handle, http_meta, &mmeta[0], &topic_num);
	if (ret != 0) {
		fprintf(stderr, "%s:%d error, down switch func return:%d\n", __FILE__, __LINE__, ret);
		goto error;
	}

	/* proxy to mqtt */
	int i;
	for (i = 0; p->mbud_fp && i < topic_num; i++) {
		PayloadBuf* rsp = query_simple(p->mbud_fp, mmeta[i].topic, mmeta[i].payload);
		FREE_PAYLOAD(mmeta[i].payload);
		if (!rsp) {
			fprintf(stderr,"%s:%d query error :%s\n",   __FILE__, __LINE__, mmeta[i].topic);
			goto error;
		}
		mmeta[i].payload = rsp;	
	}

	/* upstream switch */
	ret = handle->up_switch_func(handle, http_meta, &mmeta[0], &topic_num);
	if (ret != 0) {
		fprintf(stderr, "%s:%d error, up switch func return:%d\n", __FILE__, __LINE__, ret);
		goto error;
	}

	if (!http_meta->payload) goto error;
	char* str = cJSON_Print(http_meta->payload);
	fprintf(stderr, "%s:%d error, up switch func return:%s\n", __FILE__, __LINE__, str);
	// clean_http_meta(http_meta, 1);
	// clean_mqtt_meta(mmeta, 4);
	return str;

error:
	// clean_http_meta(http_meta, 1);
	// clean_mqtt_meta(mmeta, 4);

	return api_sample_response(500, "Failed");
}





URIHANDLER_FUNC(mod_api_uri_handler) {
    plugin_data *p = p_d;
	int req_type, ret;

	void* ptr = NULL;
	req_type = adapter_find_request(&r->uri.path, &ptr);
	if (req_type < 0) {
		goto BAD_REQ_400;
	}

	struct HttpMeta http_meta;
	memset(&http_meta, 0, sizeof(http_meta));

	ret = fill_http_meta(r, &http_meta);
	if (ret < 0) {
		goto BAD_REQ_400;
	}

	char* str = NULL;
	if (req_type == 1) {
		str = proxy_request_handle((struct HttpToMqtt*)ptr, &http_meta, p);
	}
	else {
		str = local_request_handle((struct HttpLocal*)ptr, &http_meta, NULL);
	}

	if (str) {
		http_chunk_append_mem(r, str, strlen(str));
		free(str);
		str = NULL;
	}
	else {
		http_chunk_append_mem(r, "{mmmmm}", strlen("{mmmmm}"));
	}

	r->http_status = 200;
	r->resp_body_finished = 1;
	return HANDLER_FINISHED;

	log_error(r->conf.errh, __FILE__, __LINE__, "no handler goon\n");
	return HANDLER_GO_ON;

BAD_REQ_400:
	r->http_status = 400;
	r->resp_body_finished = 1;
	return HANDLER_FINISHED;
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
	return 0;
}
