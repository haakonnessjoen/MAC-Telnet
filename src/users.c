/*
	Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
	Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License along
	with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <locale.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "mtwei.h"
#include "extra.h"
#include "users.h"
#include "utlist.h"

#define _(STRING) gettext(STRING)

struct mt_credentials *mt_users = NULL;

static int parseLine(char *line, char **username, char **password, char **salt) {
	char *user;
	char *pass;
	char *sal;

	user = strtok(line, ":");
	int userlen = strlen(user);

	if (strstr(user+userlen+1, ":") != NULL) {
		pass = strtok(NULL, ":");
		sal = strtok(NULL, "\n");
	} else {
		pass = strtok(NULL, "\n");
		sal = NULL;
	}

	if (user == NULL || pass == NULL || user[0] == '#') {
		return 0;
	}

	if (userlen > MT_CRED_USERLEN) {
		userlen = MT_CRED_USERLEN;
	}
	user[userlen] = '\0';
	if (strlen(pass) > MT_CRED_LEN) {
		pass[MT_CRED_LEN] = '\0';
	}
	if (sal != NULL && strlen(sal) > MT_CRED_SALTLEN * 2) {
		sal[MT_CRED_SALTLEN * 2] = '\0';
	}
	if (sal != NULL && strlen(pass) > MT_CRED_HASHLEN * 2) {
		pass[MT_CRED_HASHLEN * 2] = '\0';
	}

	*username = user;
	*password = pass;
	*salt = sal;

	return 1;
}

// Returns 1 if the file is ok, 0 if not
static int check_user_file(struct stat *info) {
	if (stat(USERSFILE, info) != 0) {
		fprintf(stderr, _("Error stating file %s: %s\n"), USERSFILE, strerror(errno));
		return 0;
	}

	struct passwd *pwd = getpwuid(info->st_uid);
	if (pwd == NULL) {
		fprintf(stderr, _("Error getting user information for uid %d: %s\n"), info->st_uid, strerror(errno));
		return 0;
	}

	if (strcmp(pwd->pw_name, "root") != 0) {
		fprintf(stderr, _("Error: %s is not owned by root\n"), USERSFILE);
		return 0;
	}

	if (info->st_mode & S_IWOTH || info->st_mode & S_IWGRP) {
		fprintf(stderr,
				_("Error: %s is writable by others, It should have permissions set to 0600 for better security\n"),
				USERSFILE);
		return 0;
	}

	return 1;
}

void read_userfile() {
	int lineno = 0;
	struct mt_credentials *cred, *tmp;

	struct stat info;
	int file_ok = check_user_file(&info);
	if (!file_ok) {
		int counter = 0;
		DL_COUNT(mt_users, cred, counter);
		if (counter == 0) {
			// If the file is not usable, and we have no users, we should abort
			fprintf(stderr, _("Error: %s is invalid and no users known, aborting.\n"), USERSFILE);
			exit(EXIT_FAILURE);
		}
		// If the file is not owned by root, or if it is writable by others, but we have read the users file before, we can continue
		// without the updated users file.
		fprintf(stderr, _("Warning: User file '%s' is not readable, falling back to known users.\n"), USERSFILE);
		return;
	}

	FILE *file = fopen(USERSFILE, "r");
	char line[BUFSIZ];

	if (file == NULL) {
		perror(USERSFILE);
		exit(1);
	}

	DL_FOREACH_SAFE(mt_users, cred, tmp) {
		DL_DELETE(mt_users, cred);
		free(cred);
	}

	while (fgets(line, sizeof line, file)) {
		char *user;
		char *password;
		char *salt;
		size_t size;

		lineno++;

		if (!parseLine(line, &user, &password, &salt)) {
			continue;
		}

		cred = (struct mt_credentials *)calloc(1, sizeof(struct mt_credentials));
		if (cred == NULL) {
			fprintf(stderr, _("Error allocating memory for user information\n"));
			exit(1);
		}

		/* verify that the username & password will be '\0' terminated */
		memcpy(cred->username, user, size = (strlen(user) < MT_CRED_LEN ? strlen(user) : MT_CRED_LEN - 1));
		cred->username[size] = '\0';
		if (salt != NULL) {
			if (strlen(password) != MT_CRED_HASHLEN * 2) {
				fprintf(stderr, _("Warning: Invalid password hash on line %d of user file\n"), lineno);
				free(cred);
				continue;
			}
			if (strlen(salt) != MT_CRED_SALTLEN * 2) {
				fprintf(stderr, _("Warning: Invalid salt on line %d of user file\n"), lineno);
				free(cred);
				continue;
			}
			long readlen;
			unsigned char *binsalt;
			if ((binsalt = OPENSSL_hexstr2buf(salt, &readlen)) == NULL || readlen != MT_CRED_SALTLEN) {
				fprintf(stderr, _("Warning: Invalid salt on line %d of user file\n"), lineno);
				free(cred);
				continue;
			}
			memcpy(cred->salt, binsalt, MT_CRED_SALTLEN);

			readlen = 0;
			unsigned char *binpass;
			if ((binpass = OPENSSL_hexstr2buf(password, &readlen)) == NULL || readlen != MT_CRED_HASHLEN) {
				fprintf(stderr, _("Warning: Invalid password hash on line %d of user file\n"), lineno);
				free(cred);
				continue;
			}
			memcpy(cred->password, binpass, MT_CRED_HASHLEN);
			cred->hashed = 1;
		} else {
			memcpy(cred->password, password,
				   size = (strlen(password) < MT_CRED_LEN ? strlen(password) : MT_CRED_LEN - 1));
			cred->password[size] = '\0';
		}
		DL_APPEND(mt_users, cred);
	}
	fclose(file);
}

struct mt_credentials *find_user(char *username) {
	struct mt_credentials *cred;

	DL_FOREACH(mt_users, cred) {
		if (strcmp(username, cred->username) == 0) {
			return cred;
		}
	}
	return NULL;
}

int add_user(const char *username, const char *password) {
	FILE *rfile;
	FILE *wfile;
	char line[BUFSIZ];
	char linecopy[BUFSIZ];
	unsigned char newsalt[MT_CRED_SALTLEN];
	unsigned char newhash[MT_CRED_HASHLEN];
	unsigned int md_len;
	char found = 0;
	int lineno = 0;

	// Check that the file USERSFILE is owned by root with stat(), and that it is not writable by others
	// If not, exit with failure
	struct stat info;
	int is_ok = check_user_file(&info);
	if (!is_ok) {
		exit(EXIT_FAILURE);
	}

	// Open the password file
	rfile = fopen(USERSFILE, "r");
	if (!rfile) {
		fprintf(stderr, _("Error opening password file %s: %s\n"), USERSFILE, strerror(errno));
		exit(EXIT_FAILURE);
	}
	wfile = fopen(USERSFILE ".tmp", "wb");
	if (!wfile) {
		fprintf(stderr, _("Error opening temporary password file for writing %s: %s\n"), USERSFILE ".tmp",
				strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (fchown(fileno(wfile), info.st_uid, info.st_gid) != 0) {
		fprintf(stderr, _("Error changing ownership of temporary password file %s: %s\n"), USERSFILE ".tmp",
				strerror(errno));
		fclose(wfile);
		unlink(USERSFILE ".tmp");
		exit(EXIT_FAILURE);
	}

	if (fchmod(fileno(wfile), info.st_mode) != 0) {
		fprintf(stderr, _("Error changing permissions of temporary password file %s: %s\n"), USERSFILE ".tmp",
				strerror(errno));
		fclose(wfile);
		unlink(USERSFILE ".tmp");
		exit(EXIT_FAILURE);
	}

	// Generate a random salt
	if (!RAND_bytes(newsalt, sizeof(newsalt))) {
		fprintf(stderr, _("Error generating random salt.\n"));
		exit(EXIT_FAILURE);
	}

	if (password != NULL) {
		mtwei_id(username, password, newsalt, newhash);
	}

	while (fgets(line, sizeof line, rfile)) {
		char *user;
		char *pass;
		char *sal;

		lineno++;

		memcpy(linecopy, line, sizeof linecopy);
		if (!parseLine(linecopy, &user, &pass, &sal)) {
			fputs(line, wfile);
			continue;
		}

		if (!found && strcmp(user, username) == 0) {
			if (password == NULL) {
				// Delete the user
				found = 1;
				continue;
			}
			fprintf(wfile, "%s:", username);
			char output[MT_CRED_HASHLEN * 2 + 1];
			OPENSSL_buf2hexstr_ex(output, sizeof(output), NULL, newhash, MT_CRED_HASHLEN, '\0');
			fputs(output, wfile);
			fputs(":", wfile);
			OPENSSL_buf2hexstr_ex(output, sizeof(output), NULL, newsalt, MT_CRED_SALTLEN, '\0');
			fputs(output, wfile);
			fputs("\n", wfile);
			found = 1;
		} else {
			fputs(line, wfile);
		}
	}

	// Non-existing user, append to the end of the file
	if (!found && password != NULL) {
		// Write username, salt, and hashed password to the file
		fprintf(wfile, "%s:", username);
		char output[MT_CRED_HASHLEN * 2 + 1];
		OPENSSL_buf2hexstr_ex(output, sizeof(output), NULL, newhash, MT_CRED_HASHLEN, '\0');
		fputs(output, wfile);
		fputs(":", wfile);
		OPENSSL_buf2hexstr_ex(output, sizeof(output), NULL, newsalt, MT_CRED_SALTLEN, '\0');
		fputs(output, wfile);
		fputs("\n", wfile);
	}

	// Close the password file
	fclose(wfile);
	fclose(rfile);

	// Rename the temporary file to the password file
	if (rename(USERSFILE ".tmp", USERSFILE) != 0) {
		fprintf(stderr, "Error renaming temporary password file to %s: %s\n", USERSFILE, strerror(errno));
		unlink(USERSFILE ".tmp");
		exit(EXIT_FAILURE);
	}

	return found ? 2 : 1;
}