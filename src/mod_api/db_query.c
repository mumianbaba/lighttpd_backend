#include <stdio.h>

#include "mod_api/db_query.h"
#include "log.h"

int get_user_info_from_backend(const char* username, struct UserInfo* info)
{
	if (!username || !info) goto error;

	info->username = buffer_init();
	//info->user_type = buffer_init();
	info->roles = buffer_init();
	info->digest = buffer_init();


	info->role = 0x1;
	info->user_id = 1;
	buffer_copy_string(info->username, "linuxing");
	//buffer_copy_string(info->user_type, "admin");
	buffer_copy_string(info->roles, "admin");
	buffer_copy_string(info->digest, "e1a39c9735d42a2d203b8b9732f3f795");
	return 0;

error:
	fprintf(stderr, "%s %d get user info backend failed\n", __func__, __LINE__);
	return -1;
}

void clean_user_info(struct UserInfo* info)
{
	if (!info) {
		return;
	}
	buffer_free(info->username);
	//buffer_free(info->user_type);
	buffer_free(info->roles);
	buffer_free(info->digest);

	info->username  = NULL;
	//info->user_type  = NULL;
	info->roles  = NULL;
	info->digest  = NULL;
	return;
}
