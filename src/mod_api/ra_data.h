#ifndef RA_DATA_H
#define RA_DATA_H

#include "mod_api/ra_api.h"
#include "mod_api/ra_test.h"


#define MSZIE (int)(sizeof(adapter) / sizeof(adapter[0]))


struct KeyPair s_wan_in[] = {
	{.key1 = "netmask", .key2 = "mask", .flag = 0x3},
	{.key1 = "ip", .key2 = "ip", .flag = 0x3},
	{.key1 = "gateway", .key2 = "gateway", .flag = 0x3},
	{.key1 = "dns1", .key2 = "dns", .flag = 0x3},
};

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
	},
};



static struct HttpToMqtt m_network[] = {
	{
		.h_meta = {.uri = "wanConf", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/WAN", .pair = {.list = s_wan_in, .n = 4}}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_wanConf, s_ok},
	},
	{
		.h_meta = {.uri = "lanConf", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/LAN",},
		           {.topic = "request/rasdk/DHCP",}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_lanConf, s_ok},
	},
	{
		.h_meta = {.uri = "mobileInfo", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/APN",},
		           {.topic = "request/rasdk/net4g",},
				   {.topic = "request/rasdk/net4gM",}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_mobileInfo, s_ok},
	},
	{
		.h_meta = {.uri = "networkInfo", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/WAN",},
		           {.topic = "request/rasdk/LAN",},
				   {.topic = "request/rasdk/DHCP",}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_networkInfo, s_ok},
	},
	{
		.h_meta = {.uri = "lanDeviceList", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/???????",}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_lanDeviceList, s_ok},
	},
	{
		.h_meta = {.uri = "firewallConf", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/???????",}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_firewallConf, s_ok},
	},
	{
		.h_meta = {.uri = "macFilter", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/???????",}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_macFilter, s_ok},
	},
	{
		.h_meta = {.uri = "portFilter", .role = 1,},
		.m_meta = {{.topic = "request/rasdk/???????",}},
		.down_switch_func = down_common_handle,
		.up_switch_func = up_common_handle,
		.test = {s_portFilter, s_ok},
	},
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
	{
		.id = 3,
		.root_uri = "/api/network/",
		.n = sizeof(m_network) /sizeof(m_network[0]),
		.proxy = m_network,
	},

};



#endif