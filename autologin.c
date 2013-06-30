#include <stdio.h>
#include <string.h>

#define AUTOLOGIN_PATH ".mactelnet"
#define AUTOLOGIN_MAXSTR 100
#define AUTOLOGIN_MAXPROFILES 100

struct autologin {
	char identifier[AUTOLOGIN_MAXSTR];
	char username[AUTOLOGIN_MAXSTR];
	char password[AUTOLOGIN_MAXSTR];
	char inuse:1;
	char hasUsername:1;
	char hasPassword:1;
};

struct autologin logins[AUTOLOGIN_MAXPROFILES];

enum autologin_state {
	ALS_NONE,
	ALS_IDENTIFIER,
	ALS_KEY,
	ALS_VALUE,
};
#define AL_NONE 0

int main() {
	FILE *fp;
	char c;
	int i = -1;
	char *p;
	char key[AUTOLOGIN_MAXSTR];
	char value[AUTOLOGIN_MAXSTR];
	int line_counter=1;
	enum autologin_state state = ALS_NONE;
	fp = fopen(AUTOLOGIN_PATH, "r");
	while ((c = fgetc(fp)) && !feof(fp)) {
		if (c == '#') {
			while ((c = fgetc(fp)) != '\n' && !feof(fp));
		}
		switch (state) {
			case ALS_NONE:
				if (c == '[') {
					state = ALS_IDENTIFIER;
					i++;
					p = logins[i].identifier;
				}
				break;

			case ALS_IDENTIFIER:
				if (c == ']') {
					//fprintf(stderr, "debug: identifier %s on line %d\n", logins[i].identifier, line_counter);
					state = ALS_KEY;
					memset(key, 0, AUTOLOGIN_MAXSTR);
					memset(value, 0, AUTOLOGIN_MAXSTR);
					p = key;
					logins[i].inuse = 1;
					break;
				}
				if (c == '\n') {
					fprintf(stderr, "Error on line %d in %s: New line in middle of identifier\n", line_counter, AUTOLOGIN_PATH);
					state = ALS_NONE;
					line_counter++;
					break;
				}
				*p++ = c;
				if (p - logins[i].identifier > AUTOLOGIN_MAXSTR) {
					fprintf(stderr, "Error on line %d in %s: Identifier string too long.\n", line_counter, AUTOLOGIN_PATH);
					while ((c = fgetc(fp)) != '\n' && c != ']' && !feof(fp));
					if (c == '\n') line_counter++;
					state = ALS_KEY;
					memset(key,0,AUTOLOGIN_MAXSTR);
					memset(value, 0, AUTOLOGIN_MAXSTR);
					p = key;
					break;
				}
				break;

			case ALS_KEY:
				if (p == key && c == '\n') break;
				if (c == '=') {
					state = ALS_VALUE;
					memset(value, 0, AUTOLOGIN_MAXSTR);
					p = value;
					break;
				}
				if (c == '[') {
					state = ALS_IDENTIFIER;
					i++;
					p = logins[i].identifier;
					break;
				}
				if (c == ' ') { // ignore whitespace
					break;
				}
				if (c == '\n') {
					fprintf(stderr, "Error on line %d in %s: Newline before '=' character\n", line_counter, AUTOLOGIN_PATH);
					state = ALS_KEY;
					memset(key, 0, AUTOLOGIN_MAXSTR);
					memset(value, 0, AUTOLOGIN_MAXSTR);
					p = key;
					break;
				}
				*p++ = c;
				if (p - key > AUTOLOGIN_MAXSTR) {
					fprintf(stderr, "Error on line %d in %s: Key string too long.\n", line_counter, AUTOLOGIN_PATH);
					while ((c = fgetc(fp)) != '\n' && c != '=' && !feof(fp));
					if (c == '\n') {
						state = ALS_KEY;
						memset(key, 0, AUTOLOGIN_MAXSTR);
						memset(value, 0, AUTOLOGIN_MAXSTR);
						p = key;
					} else {
						state = ALS_VALUE;
						memset(value, 0, AUTOLOGIN_MAXSTR);
						p = value;
					}
				}
				break;

			case ALS_VALUE:
				if (p == value && c == '\n') break;
				if (c == '\n') {
					if (strncasecmp(key, "user", AUTOLOGIN_MAXSTR) == 0) {
						strncpy(logins[i].username, value, AUTOLOGIN_MAXSTR);
						logins[i].hasUsername = 1;
					} else if (strncasecmp(key, "password", AUTOLOGIN_MAXSTR) == 0) {
						strncpy(logins[i].password, value, AUTOLOGIN_MAXSTR);
						logins[i].hasPassword = 1;
					} else {
						fprintf(stderr, "Warning on line %d of %s: Unknown parameter %s, ignoring.\n", line_counter, AUTOLOGIN_PATH, key);
					}
					state = ALS_KEY;
					memset(key, 0, AUTOLOGIN_MAXSTR);
					memset(value, 0, AUTOLOGIN_MAXSTR);
					p = key;
					break;
				}
				if (c == ' ') { // ignore whitespace
					break;
				}
				*p++ = c;
				if (p - value > AUTOLOGIN_MAXSTR) {
					fprintf(stderr, "Error on line %d in %s: Value string too long.\n", line_counter, AUTOLOGIN_PATH);
					while ((c = fgetc(fp)) != '\n' && !feof(fp));
					if (c == '\n') {
						state = ALS_KEY;
						memset(key, 0, AUTOLOGIN_MAXSTR);
						memset(value, 0, AUTOLOGIN_MAXSTR);
						p = key;
					}
				}
				break;
		}
		if (c == '\n') {
			line_counter++;
		}
	}
	fclose(fp);

	printf("\n\nConfig:\n");
	for (i = 0; i < 100; ++i) {
		if (logins[i].inuse) {
			printf("Profile: '%s'\n", logins[i].identifier);
			if (logins[i].hasUsername) {
				printf("\tUsername: '%s'\n", logins[i].username);
			}
			if (logins[i].hasPassword) {
				printf("\tPassword: '%s'\n", logins[i].password);
			}
			printf("\n");
		}
	}

}
