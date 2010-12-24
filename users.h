#ifndef _USERS_H
#define _USERS_H 1

#define MT_CRED_LEN 100
#define MT_CRED_MAXNUM 128

struct mt_credentials {
	char username[MT_CRED_LEN];
	char password[MT_CRED_LEN];
};

extern struct mt_credentials mt_users[MT_CRED_MAXNUM];

extern void read_userfile();
struct mt_credentials* find_user(char *username);

#endif
