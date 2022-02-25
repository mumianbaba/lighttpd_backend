#ifndef DB_QUERY_H
#define DB_QUERY_H

#include "first.h"
#include "buffer.h"

#include "cJSON.h"


struct UserInfo {
	unsigned role;
	unsigned user_id;
	buffer* username;
	buffer* realm;
	buffer* digest;
	buffer* roles;
};
int get_user_info_from_backend(const char* username, struct UserInfo* info);

void clean_user_info(struct UserInfo* info);

#endif









