//
// mod_access_token - Authentication based on signed cookie
//
// This module protects webpage from clients without valid
// cookie. By redirecting not-yet-valid clients to certain
// "logon page", you can protect any webapp without adding
// any auth code to webapp itself.
//
// Unlike mod_authcookie for Apache, this DOES NOT work
// with mod_auth_* modules due to lighttpd limitation (there's
// no way to turn 401 response into page redirection).
// This module solely relies on external "logon page" for
// authentication, and expect it to provide a valid cookie as a
// ticket for authenticated access.
//

#include "first.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "base.h"
#include "plugin.h"
#include "log.h"
#include "sys-crypto-md.h"

#include "base64.h"
#include "rand.h"
#include "http_chunk.h"
#include "http_header.h"
#include "algo_splaytree.h"
#include "configfile.h"

#include "cJSON.h"

#include "mod_api/db_query.h"
/**********************************************************************
 * data strutures
 **********************************************************************/

#define SPLAY_TREE_KEY(a) (a & (int)~(((uint32_t)1) << 31))

// module configuration
typedef struct {
	unsigned char  enable;    // cookie name to extract auth info
    int token_timeout;
	int refresh_timeout;
	int token_number;
    buffer *auth_url; // page to go when unauthorized
	buffer *deauth_url; // page to go when unauthorized
} plugin_config;


// top-level module structure
typedef struct {
    PLUGIN_DATA;
    plugin_config   conf;
	plugin_config   defaults;
    splay_tree *sptree;
    int timeout_max;
} plugin_data;


typedef struct {
    int token[4];
	unsigned role;
	buffer *username;
    buffer *field;
    unix_time64_t ts;
} access_token_sptree_node_t;



/******************************************************************************************************************
 * 
 * config operation
 *
 ******************************************************************************************************************/
static void mod_access_token_merge_config_cpv(plugin_config * const pconf, const config_plugin_value_t * const cpv) {
    switch (cpv->k_id) { /* index into static config_plugin_keys_t cpk[] */
      case 0: /* url.access-deny */
        pconf->enable = (0 != cpv->v.u);
        break;
      case 1: /* url.access-allow */
        pconf->token_timeout = (int)cpv->v.u;
        break;
      case 2: /* url.access-allow */
        pconf->token_number = (int)cpv->v.u;
        break;
      case 3: /* url.access-allow */
        pconf->refresh_timeout = (int)cpv->v.u;
        break;
      case 4: /* url.access-allow */
        if (!buffer_is_blank(cpv->v.b)) {
			pconf->auth_url = cpv->v.b;
		}
        break;
      case 5: /* url.access-allow */
        if (!buffer_is_blank(cpv->v.b)) {
			pconf->deauth_url = cpv->v.b;
		}
        break;
      default:/* should not happen */
        return;
    }
}

static void mod_access_token_merge_config(plugin_config * const pconf, const config_plugin_value_t *cpv) {
    do {
        mod_access_token_merge_config_cpv(pconf, cpv);
    } while ((++cpv)->k_id != -1);
}

// static void mod_access_token_patch_config(request_st * const r, plugin_data * const p) {
//     p->conf = p->defaults; /* copy small struct instead of memcpy() */
//     /*memcpy(&p->conf, &p->defaults, sizeof(plugin_config));*/
//     for (int i = 1, used = p->nconfig; i < used; ++i) {
//         if (config_check_cond(r, (uint32_t)p->cvlist[i].k_id))
//             mod_access_token_merge_config(&p->conf, p->cvlist + p->cvlist[i].v.u2[0]);
//     }
// }

SETDEFAULTS_FUNC(module_set_defaults) {

    static const config_plugin_keys_t cpk[] = {
      { CONST_STR_LEN("access-token.enable"),
        T_CONFIG_BOOL,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("access-token.token-timeout"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("access-token.token-number"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("access-token.refresh-timeout"),
        T_CONFIG_INT,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("access-token.auth-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ CONST_STR_LEN("access-token.deauth-url"),
        T_CONFIG_STRING,
        T_CONFIG_SCOPE_CONNECTION }
     ,{ NULL, 0,
        T_CONFIG_UNSET,
        T_CONFIG_SCOPE_UNSET }
    };

    plugin_data * const p = p_d;
    if (!config_plugin_values_init(srv, p, cpk, "mod_access_token")) {
		return HANDLER_ERROR;
	}

    /* initialize p->defaults from global config context */
    if (p->nconfig > 0 && p->cvlist->v.u2[1]) {
        const config_plugin_value_t *cpv = p->cvlist + p->cvlist->v.u2[0];
        if (-1 != cpv->k_id) {
			mod_access_token_merge_config(&p->conf, cpv);
		}
    }

	plugin_config * user_conf = &p->defaults;
	p->timeout_max = 1800;
	user_conf->token_timeout = 1200;
	user_conf->refresh_timeout = 2400;
	user_conf->token_number = 2;
	user_conf->auth_url = buffer_init();
	user_conf->deauth_url =  buffer_init();
	user_conf->enable = 1;

	buffer_copy_string(user_conf->auth_url, "/api/user/login");
	buffer_copy_string(user_conf->deauth_url, "/api/user/logout");


	log_error(srv->errh, __FILE__, __LINE__, "access token set default\n");
	log_error(srv->errh, __FILE__, __LINE__, "enable:%d\n", user_conf->enable);
	log_error(srv->errh, __FILE__, __LINE__, "token_timeout:%d\n", user_conf->token_timeout);
	log_error(srv->errh, __FILE__, __LINE__, "token_number:%d\n", user_conf->token_number);
	log_error(srv->errh, __FILE__, __LINE__, "refresh_timeout:%d\n", user_conf->refresh_timeout);
	log_error(srv->errh, __FILE__, __LINE__, "auth_url:%s\n", user_conf->auth_url ? user_conf->auth_url->ptr : "null");
	log_error(srv->errh, __FILE__, __LINE__, "deauth_url:%s\n", user_conf->deauth_url ? user_conf->deauth_url->ptr : "null");
    return HANDLER_GO_ON;
}


/******************************************************************************************************************
 * 
 * sptree node management
 *
 ******************************************************************************************************************/

static access_token_sptree_node_t * access_token_sptree_node_init(void) {
    access_token_sptree_node_t *spn = calloc(1, sizeof(*spn));
    force_assert(NULL != spn);
    spn->field = buffer_init();
	spn->username = buffer_init();
    return spn;
}

static void access_token_sptree_node_free(void *data) {
    access_token_sptree_node_t *spn = data;
    if (!spn) return;

	fprintf(stderr, "%s:%d free token:%s username:%s  create ts:%ld current ts:%ld role:%d\n",
		__FILE__, __LINE__, spn->field->ptr
		, spn->username->ptr, spn->ts, log_monotonic_secs, spn->role);

    buffer_free(spn->field);
	buffer_free(spn->username);
    free(spn);
}

static void access_token_sptree_free(splay_tree *sptree) {
    while (sptree) {
        access_token_sptree_node_free(sptree->data);
        sptree = splaytree_delete(sptree, sptree->key);
    }
}

static void
access_token_sptree_node_insert(plugin_data *p, int randtok[4],
								unix_time64_t ts, const char *username, unsigned role)
{
	access_token_sptree_node_t *spn;
    int key = SPLAY_TREE_KEY(randtok[0]);

    p->sptree = splaytree_splay(p->sptree, key);
    if (!p->sptree || p->sptree->key != key) {
        spn = access_token_sptree_node_init();
        p->sptree = splaytree_insert(p->sptree, key, spn);
    }
    else {
        /*(silently replace if hash collision; invalidate existing token)*/
		// very embarrassed
        spn = p->sptree->data;
    }

	buffer* token_buf = buffer_init();
	buffer_append_string_encoded_hex_lc(token_buf, (char *)randtok, sizeof(randtok));

    spn->ts = ts;
	spn->role = role;
    memcpy(spn->token, randtok, sizeof(spn->token));
    buffer_copy_string(spn->username, username);
	buffer_copy_string(spn->field, token_buf->ptr);
	buffer_free(token_buf);
	fprintf(stderr, "%s:%d delete token:%s username:%s timestamp:%ld role:%d\n",
				__FILE__, __LINE__, spn->field->ptr
				, spn->username->ptr, spn->ts, spn->role);
	return;
}

static access_token_sptree_node_t * token_lookup(plugin_data *p, const int *token, int num) {

    int key = SPLAY_TREE_KEY(token[0]);
    p->sptree = splaytree_splay(p->sptree, key);
    if (p->sptree && p->sptree->key == key) {
        access_token_sptree_node_t *spn = p->sptree->data;
        if (0 == memcmp(spn->token, token, num)) {
            return spn;
        }
    }
    return NULL;
}

static void token_delete(plugin_data *p, const int *token, int num)
{
    int key = token[0] & (int)~(((uint32_t)1) << 31);
    p->sptree = splaytree_splay(p->sptree, key);

    if (p->sptree && p->sptree->key == key) {

        access_token_sptree_node_t *spn = p->sptree->data;
        if (0 == memcmp(spn->token, token, num)) {
			access_token_sptree_node_free(spn);
			p->sptree = splaytree_delete(p->sptree, p->sptree->key);
        }
    }
    return;
}


/**********************************************************************
 * module interface
 **********************************************************************/

INIT_FUNC(module_init) {
    return calloc(1, sizeof(plugin_data));
}

FREE_FUNC(module_free) {
    plugin_data *p = p_d;
	if(!p) return;

	access_token_sptree_free(p->sptree);
	buffer_free(p->defaults.auth_url);
	buffer_free(p->defaults.deauth_url);
	p->defaults.auth_url = NULL;
	p->defaults.deauth_url = NULL;
    return;
}


static int authorization_extract_user(request_st *r, char* username, int len)
{
	if (!username || !r) return -1;
	memset(username,  0, len);
	buffer * d = http_header_request_get(r, HTTP_HEADER_AUTHORIZATION,
	                            CONST_STR_LEN("Authorization"));
	if (!d) return -1;

	
	char* start =strstr(d->ptr, "username=");
	if (!start) return -1;
	start += strlen("username=");
	if (*start == '"' || *start == '\'') {
		start++;
	}

	int i;
	for (i = 0 ; i < (len-1) ; i++) {
		if (*start == '\0' || *start == ',' ||  *start == '"' ||  *start == '\'') {
			break;
		}
		username[i] = *start++;
	}
	username[i] = '\0';
	return 0;
}

static buffer* authorization_extract_Token(request_st *r, int* token, int size)
{
	buffer *b; 
	b = http_header_request_get(r, HTTP_HEADER_OTHER, CONST_STR_LEN("Token"));
	if (!b) return NULL;

	size_t len = strlen(b->ptr);
	if (li_hex2bin((uint8_t *)token, size, b->ptr, len)) {
		return NULL;
	}

	buffer *token_buf = buffer_init();
	buffer_append_string_encoded_hex_lc(token_buf, (char *)token, size);
	return token_buf;
}

static inline void access_token_set_env(request_st *r, access_token_sptree_node_t* spn)
{
	char role_str[32];
	snprintf(role_str, sizeof(role_str), "0x%x", spn->role);
	http_header_env_set(r, CONST_STR_LEN("username"), spn->username->ptr, spn->username->used);
	http_header_env_set(r, CONST_STR_LEN("role"), role_str, strlen(role_str));
	return;
}

static char* api_login_response(buffer* token, buffer* roles, buffer* username)
{
	if (!token || !roles || !username) {
		return NULL;
	}
	fprintf(stderr, "login random token:%s \n", token->ptr);

	cJSON *root, *body;
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "statusCode", 200);
	cJSON_AddStringToObject(root, "statusDesc", "OK");

	body = cJSON_CreateObject();
	cJSON_AddStringToObject(body, "token", token->ptr);
	cJSON_AddStringToObject(body, "roles", roles->ptr);
	cJSON_AddStringToObject(body, "username", username->ptr);
	cJSON_AddItemToObject(root, "body", body);
	char* str = cJSON_Print(root);
	return str;
}

static char* api_logout_response(buffer* token, unsigned role, buffer* username)
{
	if (!token || !username) {
		return NULL;
	}

	fprintf(stderr, "logout random token:%s username:%s  role:%d\n",
					token->ptr, username->ptr, role);

	cJSON *root;
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "statusCode", 200);
	cJSON_AddStringToObject(root, "statusDesc", "OK");
	char* str = cJSON_Print(root);
	return str;
}

static buffer* generate_token(int* rand_token, int size, int role)
{
	buffer* token = buffer_init();
	li_rand_pseudo_bytes((unsigned char *)rand_token, size);
	
	if ((role & 0x3) == 0x3) {
		rand_token[0] |= 0x80000000;
	}
	else {
		rand_token[0] &= 0x7fffffff;
	}
	buffer_append_string_encoded_hex_lc(token, (char *)rand_token, size);
	return token;
}



URIHANDLER_FUNC(module_uri_handler) {

    plugin_data   *p = p_d;
	int token_int[4];

	/* access allowed; nothing to match */
	if (!p->conf.enable) return HANDLER_GO_ON;
	if (!r->uri.path.ptr) goto    NO_AUTH_401;

	const unix_time64_t cur_ts = log_monotonic_secs;


	if(!p->conf.auth_url || buffer_is_equal(&r->uri.path, p->conf.auth_url)) {
		/* /api/user/login to request token */
		char username[33];
		if(authorization_extract_user(r, username, sizeof(username))) {
			goto NO_AUTH_401;
		}

		struct UserInfo info;
		if(!get_user_info_from_backend(username, &info)) {
			goto NO_AUTH_401;
		}

		buffer* token = generate_token(token_int, sizeof(token_int), info.role);
		char* str = api_login_response(token, info.roles, info.username);
		if (str) {
			http_chunk_append_mem(r, str, strlen(str));
			free(str);
			str = NULL;
		}
		access_token_sptree_node_insert(p, token_int, cur_ts, username, info.role);

		clean_user_info(&info);
		buffer_free(token); token = NULL;

		r->http_status = 200;
    	r->handler_module = NULL;
		r->resp_body_finished = 1;
		return HANDLER_FINISHED;
	}

	/* all of not login api need pass through */
	buffer* token = authorization_extract_Token(r, token_int, sizeof(token_int));
	if (!token) goto NO_AUTH_401;

	access_token_sptree_node_t *spn = token_lookup(p, token_int, sizeof(token_int));
    if (NULL == spn || (cur_ts - spn->ts) > p->conf.token_timeout) {
		buffer_free(token);
		goto NO_AUTH_401;
    }

	if (!p->conf.deauth_url || buffer_is_equal(&r->uri.path, p->conf.deauth_url)) {
		/* /api/user/logout to release the token */
		char* str = api_logout_response(token, spn->role, spn->username);
		if (str) {
			http_chunk_append_mem(r, str, strlen(str));
			free(str);
			str = NULL;
		}
		r->http_status = 200;
		r->resp_body_finished = 1;
		token_delete(p, token_int, sizeof(token_int));
		buffer_free(token);
		return HANDLER_FINISHED;
	}
	access_token_set_env(r, spn);
    return HANDLER_GO_ON;

NO_AUTH_401:
	r->http_status = 401;
	r->resp_body_finished = 1;
	return HANDLER_FINISHED;
}



/**
 * remove expired nodes from splaytree
 *
 * walk tree to collect keys of expired nodes,
 * then remove expired nodes in second loop
 */

static void sptree_tag_old_entries(const splay_tree * const t, const unix_time64_t expire, int * const keys, size_t * const ndx) {
    access_token_sptree_node_t *spn;

    if (t->left)  sptree_tag_old_entries(t->left, expire, keys, ndx);
    if (t->right) sptree_tag_old_entries(t->right, expire, keys, ndx);

    spn = t->data;
    if (spn->ts < expire) keys[(*ndx)++] = t->key;
}

static void sptree_expire_nodes(plugin_data * const p, const unix_time64_t expire) {
    // assert(p->sptree);
    size_t max_ndx = 0;
    int * const keys = calloc(1, sizeof(int) * (p->conf.token_number + 16));
    force_assert(NULL != keys);

    sptree_tag_old_entries(p->sptree, expire, keys, &max_ndx);

    for (size_t i = 0; i < max_ndx; ++i) {
        p->sptree = splaytree_splay(p->sptree, keys[i]);
        access_token_sptree_node_free(p->sptree->data);
        p->sptree = splaytree_delete(p->sptree, keys[i]);
    }
    free(keys);
}

TRIGGER_FUNC(module_trigger) {
    plugin_data * const p = p_d;

	(void)srv;

	fprintf(stderr, "access token trigger\n");
	/* (scan splaytree only once every 64 seconds and not empty) */
	const unix_time64_t cur_ts = log_monotonic_secs;
    if (p->sptree && 0 == (cur_ts & 0x7)) {
        sptree_expire_nodes(p, cur_ts - p->conf.token_timeout);
		fprintf(stderr, "check the token expire\n");
	}
    return HANDLER_GO_ON;
}

int mod_access_token_plugin_init(plugin *p);
int mod_access_token_plugin_init(plugin *p) {
    p->version          = LIGHTTPD_VERSION_ID;
    p->name             = "access_token";
    p->init             = module_init;
    p->set_defaults     = module_set_defaults;
    // p->cleanup          = module_free;
    p->handle_trigger   = module_trigger;
    p->handle_uri_clean = module_uri_handler;

    return 0;
}


// log_error(r->conf.errh, __FILE__, __LINE__, "access token set default");
// log_error(r->conf.errh, __FILE__, __LINE__, "enable:%d", p->conf.enable);
// log_error(r->conf.errh, __FILE__, __LINE__, "token_timeout:%d", p->conf.token_timeout);
// log_error(r->conf.errh, __FILE__, __LINE__, "token_number:%d", p->conf.token_number);
// log_error(r->conf.errh, __FILE__, __LINE__, "refresh_timeout:%d", p->conf.refresh_timeout);
// log_error(r->conf.errh, __FILE__, __LINE__, "auth_url:%s", p->conf.auth_url ?p->conf.auth_url->ptr : "null");
// log_error(r->conf.errh, __FILE__, __LINE__, "deauth_url:%s", p->conf.deauth_url ?p->conf.deauth_url->ptr : "null");
