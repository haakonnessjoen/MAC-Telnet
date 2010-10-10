#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "users.h"
#include "config.h"


struct mt_credentials mt_users[MT_CRED_MAXNUM];

void readUserfile() {
	FILE *file = fopen(USERSFILE, "r");
	unsigned char line [BUFSIZ];
	int i = 0;

	if (file == NULL) {
		perror(USERSFILE);
		exit(1);
	}

	while ( fgets(line, sizeof line, file) ) {
		unsigned char *user;
		unsigned char *password;

		user = (unsigned char *)strtok(line, ":");
		password = (unsigned char *)strtok(NULL, "\n");

		if (user == NULL || password == NULL) {
			continue;
		}

		if (user[0] == '#')
			continue;

		memcpy(mt_users[i].username, user, strlen(user) < MT_CRED_LEN - 1? strlen(user) : MT_CRED_LEN);
		memcpy(mt_users[i++].password, password, strlen(password)  < MT_CRED_LEN - 1? strlen(password)  : MT_CRED_LEN);

		if (i == MT_CRED_MAXNUM)
			break;

		mt_users[i].username[0] = '\0';
	}
}

struct mt_credentials* findUser(unsigned char *username) {
	int i = 0;

	while (i < MT_CRED_MAXNUM && mt_users[i].username[0] != 0) {
		if (strcmp(username, mt_users[i].username) == 0) {
			return &(mt_users[i]);
		}
		i++;
	}
	return NULL;
}
