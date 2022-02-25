#ifndef RA_DATA_H
#define RA_DATA_H

#include "mod_api/ra_api.h"


#define MSZIE (int)(sizeof(adapter) / sizeof(adapter[0]))



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



#endif