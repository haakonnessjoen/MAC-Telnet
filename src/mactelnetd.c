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
#if !defined(__FreeBSD__)
#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE 600
#endif
#define _BSD_SOURCE
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE
#endif
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <libkern/OSByteOrder.h>
#define le16toh OSSwapLittleToHostInt16
#define htole32 OSSwapHostToLittleInt32
#elif defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif
#if HAVE_PATHS_H
#include <paths.h>
#endif
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#if !defined(__FreeBSD__) && !defined(__APPLE__)
#include <netinet/ether.h>
#endif
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <string.h>
#ifdef __linux__
#include <linux/if_ether.h>
#include <sys/mman.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/mman.h>
#include <pthread.h>
#include <sys/syscall.h>
#endif
#include <sys/ioctl.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/sysinfo.h>
#if defined(HAVE_LINUX_NETLINK_H)
#include <linux/netlink.h>
#endif
#endif
#include <pwd.h>
#include <utmpx.h>
#include <syslog.h>
#include <sys/utsname.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#if (HAVE_READPASSPHRASE == 1)
#include <readpassphrase.h>
#elif (HAVE_BSDREADPASSPHRASE == 1)
#include <bsd/readpassphrase.h>
#else
#warning "Falling back to getpass(3), which is marked obsolete!"
#include <unistd.h>
#endif

#include "protocol.h"
#include "console.h"
#include "interfaces.h"
#include "users.h"
#include "extra.h"
#include "utlist.h"
#include "mtwei.h"

#define PROGRAM_NAME "MAC-Telnet Daemon"

#define MAX_INSOCKETS 100

#define MT_INTERFACE_LEN 128

/* Max ~5 pings per second */
#define MT_MAXPPS MT_MNDP_BROADCAST_INTERVAL * 5

#define _(STRING) gettext(STRING)
#define gettext_noop(String) String

static int sockfd;
static int insockfd;
static int mndpsockfd;

static int pings = 0;

struct net_interface *interfaces = NULL;

static int use_raw_socket = 0;

static struct in_addr sourceip;
static struct in_addr destip;
static int sourceport;

static time_t last_mndp_time = 0;

/* Protocol data direction */
unsigned char mt_direction_fromserver = 1;

/* Anti-timeout is every 10 seconds. Give up after 15. */
#define MT_CONNECTION_TIMEOUT 15

static int use_md5 = 0;
static mtwei_state_t mtwei;

/* Connection states */
enum mt_connection_state { STATE_AUTH, STATE_CLOSED, STATE_ACTIVE };

/** Connection struct */
struct mt_connection {
	struct net_interface *interface;
	char interface_name[256];

	BIGNUM *private_key;
	uint8_t client_key[MTWEI_PUBKEY_LEN];

	unsigned short seskey;
	unsigned int incounter;
	unsigned int outcounter;
	unsigned int lastack;
	time_t lastdata;

	int terminal_mode;
	enum mt_connection_state state;
	int ptsfd;
	int slavefd;
	int pid;
	int wait_for_ack;
	int have_pass_salt;
	int invalid_login;

	char username[MT_MNDP_MAX_STRING_SIZE];
	unsigned char trypassword[32];
	unsigned char srcip[IPV4_ALEN];
	unsigned char srcmac[ETH_ALEN];
	unsigned short srcport;
	unsigned char dstmac[ETH_ALEN];
	unsigned char pass_salt[49];
	unsigned short terminal_width;
	unsigned short terminal_height;
	char terminal_type[30];

	struct mt_connection *prev;
	struct mt_connection *next;
};

static void uwtmp_login(struct mt_connection *);
static void uwtmp_logout(struct mt_connection *);

static struct mt_connection *connections_head = NULL;

static void list_add_connection(struct mt_connection *conn) {
	DL_APPEND(connections_head, conn);
}

static void list_remove_connection(struct mt_connection *conn) {
	if (connections_head == NULL) {
		return;
	}

	if (conn->state == STATE_ACTIVE && conn->ptsfd > 0) {
		close(conn->ptsfd);
	}
	if (conn->state == STATE_ACTIVE && conn->slavefd > 0) {
		close(conn->slavefd);
	}

	uwtmp_logout(conn);

	DL_DELETE(connections_head, conn);
	free(conn);
}

static struct mt_connection *list_find_connection(unsigned short seskey, unsigned char *srcmac) {
	struct mt_connection *p;

	DL_FOREACH(connections_head, p) {
		if (p->seskey == seskey && memcmp(srcmac, p->srcmac, ETH_ALEN) == 0) {
			return p;
		}
	}

	return NULL;
}

static struct net_interface *find_socket(unsigned char *mac) {
	struct net_interface *interface;

	DL_FOREACH(interfaces, interface) {
		if (memcmp(mac, interface->mac_addr, ETH_ALEN) == 0) {
			return interface;
		}
	}
	return NULL;
}

/* Setup sockets for sending on specific interfaces only */
static void setup_sockets() {
	struct net_interface *interface;

	DL_FOREACH(interfaces, interface) {
		int optval = 1;
		struct sockaddr_in si_me;
		struct ether_addr *mac = (struct ether_addr *)&(interface->mac_addr);

		if (!interface->has_mac) {
			continue;
		}

		if (interface->ipv4_addr[0] == 0) {
			// Ignore invalid ipv4 addresses
			continue;
		}

		if (!use_raw_socket) {
			interface->socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (interface->socketfd < 0) {
				continue;
			}

			if (setsockopt(interface->socketfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) == -1) {
				perror("SO_BROADCAST");
				continue;
			}

			setsockopt(interface->socketfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

			/* Initialize receiving socket on the device chosen */
			si_me.sin_family = AF_INET;
			si_me.sin_port = htons(MT_MACTELNET_PORT);
			memcpy(&(si_me.sin_addr.s_addr), interface->ipv4_addr, IPV4_ALEN);

			if (bind(interface->socketfd, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
				close(interface->socketfd);
				interface->socketfd = -1;
				fprintf(stderr, _("Error binding to %s:%d, %s\n"), inet_ntoa(si_me.sin_addr), sourceport,
						strerror(errno));
				syslog(LOG_NOTICE, _("Error binding to %s:%d on %s\n"), inet_ntoa(si_me.sin_addr), sourceport,
					   interface->name);
				continue;
			}
			syslog(LOG_NOTICE, _("Using %s to transmit packets from %s\n"), interface->name, ether_ntoa(mac));
		}
	}
}

static int send_udp(const struct mt_connection *conn, const struct mt_packet *packet) {
	if (use_raw_socket) {
		return net_send_udp(sockfd, conn->interface, conn->dstmac, conn->srcmac, &sourceip, sourceport, &destip,
							conn->srcport, packet->data, packet->size);
	} else {
		// We can't send on a socket that is not open
		if (conn->interface->socketfd < 0) {
			return 0;
		}

		/* Init SendTo struct */
		struct sockaddr_in socket_address;
		socket_address.sin_family = AF_INET;
		socket_address.sin_port = htons(conn->srcport);
		socket_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

		return sendto(conn->interface->socketfd, packet->data, packet->size, 0, (struct sockaddr *)&socket_address,
					  sizeof(socket_address));
	}
}

static int send_special_udp(struct net_interface *interface, unsigned short port, const struct mt_packet *packet) {
	unsigned char dstmac[ETH_ALEN];

	if (use_raw_socket) {
		memset(dstmac, 0xff, ETH_ALEN);
		return net_send_udp(sockfd, interface, interface->mac_addr, dstmac,
							(const struct in_addr *)&interface->ipv4_addr, port, &destip, port, packet->data,
							packet->size);
	} else {
		// We can't send on a socket that is not open
		if (interface->socketfd < 0) {
			return 0;
		}

		/* Init SendTo struct */
		struct sockaddr_in socket_address;
		socket_address.sin_family = AF_INET;
		socket_address.sin_port = htons(port);
		socket_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

		return sendto(interface->socketfd, packet->data, packet->size, 0, (struct sockaddr *)&socket_address,
					  sizeof(socket_address));
	}
}

static void display_motd() {
	FILE *fp;
	int c;

	if ((fp = fopen("/etc/motd", "r"))) {
		while ((c = getc(fp)) != EOF) {
			putchar(c);
		}
		fclose(fp);
	}
}

static void display_nologin() {
	FILE *fp;
	int c;

	if ((fp = fopen(_PATH_NOLOGIN, "r"))) {
		while ((c = getc(fp)) != EOF) {
			putchar(c);
		}
		fclose(fp);
	}
}

static void uwtmp_login(struct mt_connection *conn) {
	struct utmpx utent;
	struct timeval tv;
	pid_t pid;

	pid = getpid();

	char *line = ttyname(conn->slavefd);
	if (strncmp(line, "/dev/", 5) == 0) {
		line += 5;
	}

	/* Setup utmp struct */
	memset((void *)&utent, 0, sizeof(utent));
	utent.ut_type = USER_PROCESS;
	utent.ut_pid = pid;
	strncpy(utent.ut_user, conn->username, sizeof(utent.ut_user));
	strncpy(utent.ut_line, line, sizeof(utent.ut_line));
	strncpy(utent.ut_id, utent.ut_line + 3, sizeof(utent.ut_id));
	strncpy(utent.ut_host, ether_ntoa((const struct ether_addr *)conn->srcmac), sizeof(utent.ut_host));
	gettimeofday(&tv, NULL);
	utent.ut_tv.tv_sec = tv.tv_sec;
	utent.ut_tv.tv_usec = tv.tv_usec;

	/* Update utmp and/or wtmp */
	setutxent();
	pututxline(&utent);
	endutxent();

#if defined(HAVE_UPDWTMPX)
	updwtmpx(_PATH_WTMP, &utent);
#elif defined(HAVE_UPDWTMP)
	updwtmp(_PATH_WTMP, &utent);
#endif
}

static void uwtmp_logout(struct mt_connection *conn) {
	if (conn->pid > 0) {
		struct utmpx *utentp;
		struct utmpx utent;
		setutxent();

		while ((utentp = getutxent()) != NULL) {
			if (utentp->ut_pid == conn->pid && utentp->ut_id[0]) {
				break;
			}
		}

		if (utentp) {
			utent = *utentp;

			utent.ut_type = DEAD_PROCESS;
			utent.ut_tv.tv_sec = time(NULL);

			pututxline(&utent);
			endutxent();

#if defined(HAVE_UPDWTMPX)
			updwtmpx(_PATH_WTMP, &utent);
#elif defined(HAVE_UPDWTMP)
			updwtmp(_PATH_WTMP, &utent);
#endif
		}
	}
}

static void abort_connection(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, char *message) {
	struct mt_packet pdata;

	init_packet(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, message, strlen(message));
	send_udp(curconn, &pdata);

	/* Make connection time out; lets the previous message get acked before disconnecting */
	curconn->state = STATE_CLOSED;
	init_packet(&pdata, MT_PTYPE_END, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	send_udp(curconn, &pdata);
}

static void user_login(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	struct mt_packet pdata;
	unsigned char hashsum[32];
	char hashdata[100];
	struct mt_credentials *user = NULL;
	char *slavename;
	int act_pass_len;

	/* Reparse user file before each login */
	read_userfile();

	if (!curconn->invalid_login && (user = find_user(curconn->username)) != NULL) {
		EVP_MD_CTX *context;
		const EVP_MD *md;
		unsigned int md_len;

#if defined(_POSIX_MEMLOCK_RANGE) && _POSIX_MEMLOCK_RANGE > 0
		mlock(hashdata, sizeof(hashdata));
		mlock(hashsum, sizeof(hashsum));
		mlock(user->password, sizeof(user->password));
#endif

		/* calculate the password's actual length */
		act_pass_len = strlen(user->password);
		act_pass_len = act_pass_len <= 82 ? act_pass_len : 82;

		if (use_md5 && user->hashed == 0) {
			/* Concat string of 0 + password + pass_salt */
			hashdata[0] = 0;
			memcpy(hashdata + 1, user->password, act_pass_len);
			memcpy(hashdata + 1 + act_pass_len, curconn->pass_salt, 16);

			/* Generate md5 sum of md5data with a leading 0 */
			md = EVP_get_digestbyname("md5");
			// TODO: check if md is NULL
			context = EVP_MD_CTX_new();
			// TODO: check if context is NULL
			EVP_DigestInit_ex(context, md, NULL);
			EVP_DigestUpdate(context, hashdata, 1 + act_pass_len + 16);
			EVP_DigestFinal_ex(context, hashsum + 1, &md_len);
			EVP_MD_CTX_free(context);
			hashsum[0] = 0;
		} else if (use_md5 && user->hashed == 1) {
			// Provoke invalid login response
			user = NULL;
			syslog(LOG_NOTICE, _("(%d) User %s tried to login with md5 authentication, but user is not saved in plaintext"), curconn->seskey, curconn->username);
		} else {
			if (user->hashed == 1) {
				// copy validator from userfile
				memcpy(hashdata, user->password, 32);
				mtwei_docryptos(&mtwei, curconn->private_key, curconn->client_key, curconn->pass_salt,
								(uint8_t *)hashdata, hashsum);
			} else {
				mtwei_id(curconn->username, user->password, curconn->pass_salt + MTWEI_PUBKEY_LEN, (uint8_t *)hashdata);
				mtwei_docryptos(&mtwei, curconn->private_key, curconn->client_key, curconn->pass_salt,
								(uint8_t *)hashdata, hashsum);
			}
		}
	}

	init_packet(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	curconn->outcounter += add_control_packet(&pdata, MT_CPTYPE_END_AUTH, NULL, 0);
	send_udp(curconn, &pdata);

	if (user == NULL || memcmp(hashsum, curconn->trypassword, use_md5 ? 17 : 32) != 0) {
		syslog(LOG_NOTICE, _("(%d) Invalid login by %s."), curconn->seskey, curconn->username);

		/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
		abort_connection(curconn, pkthdr, _("Login failed, incorrect username or password\r\n"));

		/* TODO: should wait some time (not with sleep) before returning, to minimalize brute force attacks */
		return;
	}

	/* User is logged in */
	curconn->state = STATE_ACTIVE;

	/* Enter terminal mode */
	curconn->terminal_mode = 1;

	/* Open pts handle */
	curconn->ptsfd = posix_openpt(O_RDWR);
	if (curconn->ptsfd == -1 || grantpt(curconn->ptsfd) == -1 || unlockpt(curconn->ptsfd) == -1) {
		syslog(LOG_ERR, "posix_openpt: %s", strerror(errno));
		/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
		abort_connection(curconn, pkthdr, _("Terminal error\r\n"));
		return;
	}

	/* Get file path for our pts */
	slavename = ptsname(curconn->ptsfd);
	if (slavename != NULL) {
		pid_t pid;
		struct stat sb;
		struct passwd srcuser;
		struct passwd *user;
		const size_t bufsize = 16384;
		char * buffer;

		buffer = (char *)malloc(bufsize);
		if (buffer == NULL) {
			syslog(LOG_CRIT, _("(%d) Error allocating memory."), curconn->seskey);
			/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
			abort_connection(curconn, pkthdr, _("System error, out of memory\r\n"));
			return;
		}

		// TODO: support ERANGE
		if (getpwnam_r(curconn->username, &srcuser, buffer, bufsize, &user) != 0 || user == NULL) {
			syslog(LOG_WARNING, _("(%d) Login ok, but local user not accessible (%s)."), curconn->seskey,
				   curconn->username);
			/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
			abort_connection(curconn, pkthdr, _("Error: Local user not accessible\r\n"));
			free(buffer);
			return;
		}

		/* Change the owner of the slave pts */
		chown(slavename, user->pw_uid, user->pw_gid);

		curconn->slavefd = open(slavename, O_RDWR);
		if (curconn->slavefd == -1) {
			syslog(LOG_ERR, _("Error opening %s: %s"), slavename, strerror(errno));
			/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
			free(buffer);
			abort_connection(curconn, pkthdr, _("Error opening terminal\r\n"));
			list_remove_connection(curconn);
			return;
		}

		if ((pid = fork()) == 0) {
			struct net_interface *interface;

			/* Add login information to utmp/wtmp */
			uwtmp_login(curconn);

			syslog(LOG_INFO, _("(%d) User %s logged in."), curconn->seskey, curconn->username);

			/* Initialize terminal environment */
			setenv("USER", user->pw_name, 1);
			setenv("HOME", user->pw_dir, 1);
			setenv("SHELL", user->pw_shell, 1);
			setenv("TERM", curconn->terminal_type, 1);
			close(sockfd);
			close(insockfd);

			DL_FOREACH(interfaces, interface) {
				if (interface->socketfd > 0) {
					close(interface->socketfd);
				}
			}
			setsid();

			/* Don't let shell process inherit slavefd */
			fcntl(curconn->slavefd, F_SETFD, FD_CLOEXEC);
			close(curconn->ptsfd);

			/* Redirect STDIN/STDIO/STDERR */
			close(0);
			dup(curconn->slavefd);
			close(1);
			dup(curconn->slavefd);
			close(2);
			dup(curconn->slavefd);

			/* Set controlling terminal */
			ioctl(0, TIOCSCTTY, 1);
			tcsetpgrp(0, getpid());

			/* Set user id/group id */
			if ((setgid(user->pw_gid) != 0) || (setuid(user->pw_uid) != 0)) {
				syslog(LOG_ERR, _("(%d) Could not log in %s (%d:%d): setuid/setgid: %s"), curconn->seskey,
					   curconn->username, user->pw_uid, user->pw_gid, strerror(errno));
				/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
				abort_connection(curconn, pkthdr, _("Internal error\r\n"));
				exit(0);
			}

			/* Abort login if /etc/nologin exists */
			if (stat(_PATH_NOLOGIN, &sb) == 0 && getuid() != 0) {
				syslog(LOG_NOTICE, _("(%d) User %s disconnected with " _PATH_NOLOGIN " message."), curconn->seskey,
					   curconn->username);
				display_nologin();
				curconn->state = STATE_CLOSED;
				init_packet(&pdata, MT_PTYPE_END, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey,
							curconn->outcounter);
				send_udp(curconn, &pdata);
				exit(0);
			}

			/* Display MOTD */
			display_motd();

			chdir(user->pw_dir);

			/* Spawn shell */
			/* TODO: Maybe use "login -f USER" instead? renders motd and executes shell correctly for system */
			execl(user->pw_shell, user->pw_shell, "-", (char *)0);
			exit(0);  // just to be sure.
		}
		free(buffer);
		close(curconn->slavefd);
		curconn->pid = pid;
		set_terminal_size(curconn->ptsfd, curconn->terminal_width, curconn->terminal_height);
	}
}

/* sigh */
void write_wrapped(int file, const unsigned char *str, int len) {
	ssize_t x = write(file, str, len);
	(void)x;
}

static void handle_data_packet(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, int data_len) {
	struct mt_mactelnet_control_hdr cpkt;
	struct mt_packet pdata;
	unsigned char *data = pkthdr->data;
	unsigned int act_size = 0;
	int got_user_packet = 0;
	int got_pass_packet = 0;
	int got_width_packet = 0;
	int got_height_packet = 0;
	int success;

	/* Parse first control packet */
	success = parse_control_packet(data, data_len - MT_HEADER_LEN, &cpkt);

	while (success) {
		if (cpkt.cptype == MT_CPTYPE_TERM_WIDTH && cpkt.length >= 2) {
			unsigned short width;

			memcpy(&width, cpkt.data, 2);
			curconn->terminal_width = le16toh(width);
			got_width_packet = 1;

		} else if (cpkt.cptype == MT_CPTYPE_TERM_HEIGHT && cpkt.length >= 2) {
			unsigned short height;

			memcpy(&height, cpkt.data, 2);
			curconn->terminal_height = le16toh(height);
			got_height_packet = 1;

		} else if (cpkt.cptype == MT_CPTYPE_TERM_TYPE) {
			memcpy(curconn->terminal_type, cpkt.data, act_size = (cpkt.length > 30 - 1 ? 30 - 1 : cpkt.length));
			curconn->terminal_type[act_size] = 0;

		} else if (cpkt.cptype == MT_CPTYPE_PLAINDATA) {
			/* relay data from client to shell */
			if (curconn->state == STATE_ACTIVE && curconn->ptsfd != -1) {
				write_wrapped(curconn->ptsfd, cpkt.data, cpkt.length);
			}

		} else if (curconn->state == STATE_AUTH) {
			if (use_md5 == 1 && cpkt.cptype == MT_CPTYPE_BEGINAUTH) {
				int plen, i;
				if (!curconn->have_pass_salt) {
					for (i = 0; i < 16; ++i) {
						curconn->pass_salt[i] = rand() % 256;
					}
					curconn->have_pass_salt = 1;

					memset(curconn->trypassword, 0, sizeof(curconn->trypassword));
				}
				init_packet(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey,
							curconn->outcounter);
				plen = add_control_packet(&pdata, MT_CPTYPE_PASSSALT, (curconn->pass_salt), 16);
				curconn->outcounter += plen;

				send_udp(curconn, &pdata);

			} else if (use_md5 == 0 && cpkt.cptype == MT_CPTYPE_BEGINAUTH) {
				/* Ignore, the client wil immediately send a passsalt/encryption key control packet after this */
			} else if (use_md5 == 0 && cpkt.cptype == MT_CPTYPE_PASSSALT && cpkt.length > MTWEI_PUBKEY_LEN + 1) {
				strncpy(curconn->username, (const char *)cpkt.data, cpkt.length - MTWEI_PUBKEY_LEN);
				if (cpkt.length - strlen(curconn->username) - 1 == MTWEI_PUBKEY_LEN) {
					memcpy(curconn->client_key, cpkt.data + strlen(curconn->username) + 1, MTWEI_PUBKEY_LEN);

					int plen;
					size_t i;
					for (i = 0; i < sizeof(curconn->pass_salt); ++i) {
						curconn->pass_salt[i] = rand() % 256;
					}

					/* Reparse user file before each login */
					read_userfile();

					struct mt_credentials *user;
					if ((user = find_user(curconn->username)) != NULL) {
						curconn->have_pass_salt = 1;
						uint8_t validator[32];

						if (user->hashed) {
							memcpy(validator, user->password, 32);
							memcpy(curconn->pass_salt + MTWEI_PUBKEY_LEN, user->salt, 16);
						} else {
							mtwei_id(curconn->username, user->password, curconn->pass_salt + MTWEI_PUBKEY_LEN,
									 validator);
						}
						curconn->private_key = mtwei_keygen(&mtwei, curconn->pass_salt, validator);
					} else {
						/* Continue auth flow, so we do not let an attacker figure out if the user exists or not.
						   we need to set a fake private key, so we can continue the auth flow until the user sends
						   password, then we can send "invalid login" message, and disconnect the user. */
						curconn->have_pass_salt = 1;
						curconn->invalid_login = 1;
						uint8_t validator[32];
						char username[33];
						RAND_bytes((unsigned char*)username, 32);
						username[32] = 0;
						char password[33];
						RAND_bytes((unsigned char*)password, 32);
						password[32] = 0;

						mtwei_id(username, password, curconn->pass_salt + MTWEI_PUBKEY_LEN, validator);
						curconn->private_key = mtwei_keygen(&mtwei, curconn->pass_salt, validator);
					}

					init_packet(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey,
								curconn->outcounter);
					plen = add_control_packet(&pdata, MT_CPTYPE_PASSSALT, (curconn->pass_salt), 49);
					curconn->outcounter += plen;

					send_udp(curconn, &pdata);
				} else {
					syslog(LOG_NOTICE, _("(%d) Invalid mtwei key by %s."), curconn->seskey, curconn->username);
					// Time out connection
					curconn->state = STATE_CLOSED;
				}

			} else if (cpkt.cptype == MT_CPTYPE_USERNAME) {
				memcpy(
					curconn->username, cpkt.data,
					act_size = (cpkt.length > MT_MNDP_MAX_STRING_SIZE - 1 ? MT_MNDP_MAX_STRING_SIZE - 1 : cpkt.length));
				curconn->username[act_size] = 0;
				got_user_packet = 1;

			} else if (cpkt.cptype == MT_CPTYPE_PASSWORD && (cpkt.length == 17 || cpkt.length == 32)) {
#if defined(_POSIX_MEMLOCK_RANGE) && _POSIX_MEMLOCK_RANGE > 0
				mlock(curconn->trypassword, cpkt.length);
#endif
				memcpy(curconn->trypassword, cpkt.data, cpkt.length);
				got_pass_packet = 1;

			} else if (cpkt.cptype == MT_CPTYPE_PASSWORD && cpkt.length == 0) {
				got_pass_packet = 1;
				curconn->invalid_login = 1;
			} else {
				syslog(LOG_WARNING, _("(%d) Unhandeled control packet type: %d, length: %d"), curconn->seskey,
					   cpkt.cptype, cpkt.length);
			}
		} else {
			syslog(LOG_WARNING, _("(%d) Unhandeled control packet type: %d, in state: %d, length: %d"), curconn->seskey,
				   curconn->state, cpkt.cptype, cpkt.length);
		}

		/* Parse next control packet */
		success = parse_control_packet(NULL, 0, &cpkt);
	}

	if (got_user_packet && got_pass_packet) {
		user_login(curconn, pkthdr);
	}

	if (curconn->state == STATE_ACTIVE && (got_width_packet || got_height_packet)) {
		set_terminal_size(curconn->ptsfd, curconn->terminal_width, curconn->terminal_height);
	}
}

static void handle_packet(unsigned char *data, int data_len, const struct sockaddr_in *address) {
	struct mt_mactelnet_hdr pkthdr;
	struct mt_connection *curconn = NULL;
	struct mt_packet pdata;
	struct net_interface *interface;

	/* Check for minimal size */
	if (data_len < MT_HEADER_LEN - 4) {
		return;
	}
	parse_packet(data, &pkthdr);

	/* Drop packets not belonging to us */
	if ((interface = find_socket(pkthdr.dstaddr)) == NULL) {
		return;
	}

	switch (pkthdr.ptype) {
		case MT_PTYPE_PING:
			if (pings++ > MT_MAXPPS) {
				/* Don't want it to wrap around back to the valid range */
				pings--;
				break;
			}
			init_pongpacket(&pdata, (unsigned char *)&(pkthdr.dstaddr), (unsigned char *)&(pkthdr.srcaddr));
			add_packetdata(&pdata, pkthdr.data - 4, data_len - (MT_HEADER_LEN - 4));
			{
				if (index >= 0) {
					send_special_udp(interface, MT_MACTELNET_PORT, &pdata);
				}
			}
			break;

		case MT_PTYPE_SESSIONSTART:
			curconn = list_find_connection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn != NULL) {
				/* Ignore multiple session starts from the same sender, this can be same mac but different interface */
				break;
			}
			syslog(LOG_DEBUG, _("(%d) New connection from %s."), pkthdr.seskey,
				   ether_ntoa((struct ether_addr *)&(pkthdr.srcaddr)));
			curconn = calloc(1, sizeof(struct mt_connection));
			curconn->seskey = pkthdr.seskey;
			curconn->lastdata = time(NULL);
			curconn->state = STATE_AUTH;
			curconn->interface = interface;
			strncpy(curconn->interface_name, interface->name, 254);
			curconn->interface_name[255] = '\0';
			memcpy(curconn->srcmac, pkthdr.srcaddr, ETH_ALEN);
			memcpy(curconn->srcip, &(address->sin_addr), IPV4_ALEN);
			curconn->srcport = htons(address->sin_port);
			memcpy(curconn->dstmac, pkthdr.dstaddr, ETH_ALEN);

			list_add_connection(curconn);

			init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
			send_udp(curconn, &pdata);
			break;

		case MT_PTYPE_END:
			curconn = list_find_connection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}
			if (curconn->state != STATE_CLOSED) {
				init_packet(&pdata, MT_PTYPE_END, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				send_udp(curconn, &pdata);
			}
			syslog(LOG_DEBUG, _("(%d) Connection closed."), curconn->seskey);
			list_remove_connection(curconn);
			return;

		case MT_PTYPE_ACK:
			curconn = list_find_connection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}

			if (pkthdr.counter <= curconn->outcounter) {
				curconn->wait_for_ack = 0;
				curconn->lastack = pkthdr.counter;
			}

			if (time(0) - curconn->lastdata > 9 || pkthdr.counter == curconn->lastack) {
				// Answer to anti-timeout packet
				init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				send_udp(curconn, &pdata);
			}
			curconn->lastdata = time(NULL);
			return;

		case MT_PTYPE_DATA:
			curconn = list_find_connection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}
			curconn->lastdata = time(NULL);

			/* now check the right size */
			if (data_len < MT_HEADER_LEN) {
				/* Ignore illegal packet */
				return;
			}

			/* ack the data packet */
			init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey,
						pkthdr.counter + (data_len - MT_HEADER_LEN));
			send_udp(curconn, &pdata);

			/* Accept first packet, and all packets greater than incounter, and if counter has
			wrapped around. */
			if (curconn->incounter == 0 || pkthdr.counter > curconn->incounter ||
				(curconn->incounter - pkthdr.counter) > 16777216) {
				curconn->incounter = pkthdr.counter;
			} else {
				/* Ignore double or old packets */
				return;
			}

			handle_data_packet(curconn, &pkthdr, data_len);
			break;
		default:
			if (curconn) {
				syslog(LOG_WARNING, _("(%d) Unhandeled packet type: %d"), curconn->seskey, pkthdr.ptype);
				init_packet(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				send_udp(curconn, &pdata);
			}
	}
	if (0 && curconn != NULL) {
		printf("Packet, incounter %d, outcounter %d\n", curconn->incounter, curconn->outcounter);
	}
}

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PACKAGE_VERSION "\n");
}

void mndp_broadcast() {
	struct mt_packet pdata;
	struct utsname s_uname;
	struct net_interface *interface;
	unsigned int uptime;
#if defined(__APPLE__)
	int mib[] = {CTL_KERN, KERN_BOOTTIME};
	struct timeval boottime;
	size_t tv_size = sizeof(boottime);
	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]), &boottime, &tv_size, NULL, 0) == -1) {
		return;
	}
	uptime = htole32(boottime.tv_sec);
#elif defined(__linux__)
	struct sysinfo s_sysinfo;

	if (sysinfo(&s_sysinfo) != 0) {
		return;
	}

	/* Seems like ping uptime is transmitted as little endian? */
	uptime = htole32(s_sysinfo.uptime);
#else
	struct timespec ts;

	if (clock_gettime(CLOCK_UPTIME, &ts) != -1) {
		uptime = htole32(((unsigned int)ts.tv_sec));
	}
#endif

	if (uname(&s_uname) != 0) {
		return;
	}

	int num_devices = 0;
	int num_devices_sent = 0;
	DL_FOREACH(interfaces, interface) {
		struct mt_mndp_hdr *header = (struct mt_mndp_hdr *)&(pdata.data);

		if (interface->has_mac == 0) {
			continue;
		}

		num_devices++;
		mndp_init_packet(&pdata, 0, 1);
		mndp_add_attribute(&pdata, MT_MNDPTYPE_ADDRESS, interface->mac_addr, ETH_ALEN);
		mndp_add_attribute(&pdata, MT_MNDPTYPE_IDENTITY, s_uname.nodename, strlen(s_uname.nodename));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_VERSION, s_uname.release, strlen(s_uname.release));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_PLATFORM, PLATFORM_NAME, strlen(PLATFORM_NAME));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_HARDWARE, s_uname.machine, strlen(s_uname.machine));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_TIMESTAMP, &uptime, 4);
		mndp_add_attribute(&pdata, MT_MNDPTYPE_SOFTID, MT_SOFTID_MACTELNET, strlen(MT_SOFTID_MACTELNET));
		mndp_add_attribute(&pdata, MT_MNDPTYPE_IFNAME, interface->name, strlen(interface->name));

		header->cksum = in_cksum((unsigned short *)&(pdata.data), pdata.size);
		if (send_special_udp(interface, MT_MNDP_PORT, &pdata) > 0) {
			num_devices_sent++;
		}
	}

	if (num_devices > 0 && num_devices_sent == 0) {
		syslog(LOG_WARNING, _("Was not able to send any MNDP packets"));
	}
}

void sigterm_handler() {
	struct mt_connection *p;
	struct mt_packet pdata;
	struct net_interface *interface, *tmp;
	/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
	char message[] = gettext_noop("\r\n\r\nDaemon shutting down.\r\n");

	syslog(LOG_NOTICE, _("Daemon shutting down"));

	DL_FOREACH(connections_head, p) {
		if (p->state == STATE_ACTIVE) {
			init_packet(&pdata, MT_PTYPE_DATA, p->interface->mac_addr, p->srcmac, p->seskey, p->outcounter);
			add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, _(message), strlen(_(message)));
			send_udp(p, &pdata);

			init_packet(&pdata, MT_PTYPE_END, p->interface->mac_addr, p->srcmac, p->seskey, p->outcounter);
			send_udp(p, &pdata);
		}
	}

	/* Doesn't hurt to tidy up */
	close(sockfd);
	close(insockfd);
	if (!use_raw_socket) {
		DL_FOREACH(interfaces, interface) {
			if (interface->socketfd > 0)
				close(interface->socketfd);
		}
	}
	DL_FOREACH_SAFE(interfaces, interface, tmp) {
		DL_DELETE(interfaces, interface);
		free(interface);
	}
	closelog();
	exit(0);
}

void sighup_handler() {
	struct mt_connection *p, *conntmp;

	syslog(LOG_NOTICE, _("SIGHUP: Reloading interfaces"));

	if (!use_raw_socket) {
		struct net_interface *interface, *tmp;
		DL_FOREACH_SAFE(interfaces, interface, tmp) {
			close(interface->socketfd);
			DL_DELETE(interfaces, interface);
			free(interface);
		}
		interfaces = NULL;
	}

// If we don't have network auto-reload, we need to exit if we can't find any interfaces
#if !defined(HAVE_LINUX_NETLINK_H) || !defined(__linux__) || !defined(__APPLE__)
	if (net_get_interfaces(&interfaces) <= 0) {
		syslog(LOG_ERR, _("No devices found! Exiting.\n"));
		exit(1);
	}
#endif

	setup_sockets();

	/* Reassign outgoing interfaces to connections again, since they may have changed */
	DL_FOREACH_SAFE(connections_head, p, conntmp) {
		if (p->interface_name[0] != 0) {
			struct net_interface *interface = net_get_interface_ptr(&interfaces, p->interface_name, 0);
			if (interface != NULL) {
				p->interface = interface;
			} else {
				syslog(LOG_NOTICE, _("(%d) Connection closed because interface %s is gone."), p->seskey,
					   p->interface_name);
				list_remove_connection(p);
			}
		}
	}
}

static int main_add_user(char *username, char *password) {
	char user[32];
	char pwd[200];

	if (username == NULL) {
		printf(_("Username: "));
		fflush(stdout);
		(void)scanf("%31s", user);

		if (strlen(user) == 0) {
			fprintf(stderr, _("Username must be specified.\n"));
			return 1;
		}
		username = user;
	}

	if (strlen(username) > 32) {
		fprintf(stderr, _("Username too long.\n"));
		return 1;
	}

	struct passwd *user_entry = getpwnam(username);
	if (user_entry == NULL) {
		fprintf(stderr, _("Warning: Local user '%s' does not exist.\n"), username);
	}

	if (password == NULL) {
#if (HAVE_READPASSPHRASE == 1 || HAVE_BSDREADPASSPHRASE == 1)
		char *tmp = readpassphrase(_("Password: "), (char *)&pwd, 200, RPP_ECHO_OFF);
#else
		char *tmp = getpass(_("Password: "));
#endif
		if (tmp == NULL || strlen(tmp) == 0) {
			fprintf(stderr, _("Password must be specified.\n"));
			return 1;
		}
		password = tmp;
	}

	int result = add_user(username, password);
	if (result == 1) {
		printf(_("User %s was added.\n"), username);
	} else if (result == 2) {
		printf(_("User %s was updated.\n"), username);
	} else {
		fprintf(stderr, _("Failed to add user %s.\n"), username);
		return 1;
	}
	return 0;
}

static int main_delete_user(char *username) {
	if (username == NULL) {
		fprintf(stderr, _("Username must be specified.\n"));
		return 1;
	}

	int result = add_user(username, NULL);
	if (result == 2) {
		printf(_("User %s was deleted.\n"), username);
	} else if (result == 1) {
		printf(_("User %s did not exist.\n"), username);
	} else {
		fprintf(stderr, _("Failed to delete user %s.\n"), username);
		return 1;
	}
	return 0;
}

static int main_list_users() {
	struct mt_credentials *user;

	printf(_("Users:\n"));
	DL_FOREACH(mt_users, user) {
		struct passwd *user_entry = getpwnam(user->username);

		if (user_entry == NULL) {
			printf("\t%s (%s)\n", user->username, _("local user not found!"));
		} else if (user_entry->pw_uid == 0 || user_entry->pw_gid == 0) {
			printf("\t%s (%s)\n", user->username, _("has root access!"));
		} else if (!user->hashed) {
			printf("\t%s (%s)\n", user->username, _("plain-text password!"));
		} else {
			printf("\t%s\n", user->username);
		}
	}
	printf("\n");
	return 0;
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main(int argc, char **argv) {
	int result;
	struct sockaddr_in si_me;
	struct sockaddr_in si_me_mndp;
	struct timeval timeout;
	struct mt_packet pdata;
	struct net_interface *interface;
	fd_set read_fds;
	int c, optval = 1;
	int print_help = 0;
	int foreground = 0;
	int interface_count = 0;
	char add_user = 0;
	char list_users = 0;
	char *add_user_name = NULL;
	char *add_user_password = NULL;
	char *delete_user = NULL;

	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	textdomain(PACKAGE);

#if !defined(__APPLE__)
	while ((c = getopt(argc, argv, "fnovh?")) != -1) {
#else
	while ((c = getopt(argc, argv, "novhlau:p:d:")) != -1) {
#endif
		switch (c) {
			case 'f':
				foreground = 1;
				break;

			case 'n':
				use_raw_socket = 1;
				break;

			case 'o':
				use_md5 = 1;
				break;

			case 'v':
				print_version();
				exit(0);
				break;

			case 'a':
				add_user = 1;
				break;

			case 'u':
				add_user_name = optarg;
				break;

			case 'p':
				add_user_password = optarg;
				break;

			case 'd':
				delete_user = optarg;
				break;

			case 'l':
				list_users = 1;
				break;

			case 'h':
			case '?':
				print_help = 1;
				break;
		}
	}

	if (print_help) {
		print_version();
		fprintf(stderr, _("Usage: %s [-fnoh]|-a [-u <user>|-p <password>]|[-d <user>]\n"), argv[0]);

		if (print_help) {
#if !defined(__APPLE__)
			/*_ This is the usage output for operating systems other than MacOS */
			fprintf(stderr, _("\nParameters:\n"
							  "  -f            Run process in foreground.\n"
							  "  -n            Do not use broadcast packets. Just a tad less insecure.\n"
							  "  -o            Use MD5 for password hashing.\n"
							  "  -l            List users from userfile.\n"
							  "  -a            Add a new user.\n"
							  "  -u [user]     Optionally set username to add with -a.\n"
							  "  -p [password] Optionally set password for -a command.\n"
							  "  -d [user]     Delete user.\n"
							  "  -h            This help.\n"
							  "\n\nIf any of -a, -d, -l or -h is specified, the server will not start.\n"
							  "\n"));
#else
			/*_ This is the usage output for MacOS which always runs in the forground
				as it should be daemonized by launchd */
			fprintf(stderr, _("\nParameters:\n"
							  "  -n            Do not use broadcast packets. Just a tad less insecure.\n"
							  "  -o            Use MD5 for password hashing.\n"
							  "  -l            List users from userfile.\n"
							  "  -a            Add a new user.\n"
							  "  -u [user]     Optionally set username to add with -a.\n"
							  "  -p [password] Optionally set password for -a command.\n"
							  "  -d [user]     Delete user.\n"
							  "  -h            This help.\n"
							  "\n\nIf any of -a, -d, -l or -h is specified, the server will not start.\n"
							  "\n"));
#endif
		}
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, _("You need to have root privileges to use %s.\n"), argv[0]);
		return 1;
	}

	/* Try to read user file */
	read_userfile();

	if (add_user) {
		return main_add_user(add_user_name, add_user_password);
	} else if (delete_user) {
		return main_delete_user(delete_user);
	} else if (list_users) {
		return main_list_users();
	}

	/* Seed randomizer */
	srand(time(NULL));

	if (use_md5 == 0) {
#if defined(_POSIX_MEMLOCK_RANGE) && _POSIX_MEMLOCK_RANGE > 0
		mlock(&mtwei, sizeof(mtwei));
#endif
		mtwei_init(&mtwei);
	}

	if (use_raw_socket) {
		/* Transmit raw packets with this socket */
		sockfd = net_init_raw_socket();
	}

	/* Receive regular udp packets with this socket */
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (insockfd < 0) {
		perror("insockfd");
		return 1;
	}

	/* Set source port */
	sourceport = MT_MACTELNET_PORT;

	/* Listen address*/
	inet_pton(AF_INET, (char *)"0.0.0.0", &sourceip);

	/* Set up global info about the connection */
	inet_pton(AF_INET, (char *)"255.255.255.255", &destip);

	/* Initialize receiving socket on the device chosen */
	memset((char *)&si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(sourceport);
	memcpy(&(si_me.sin_addr), &sourceip, IPV4_ALEN);

	setsockopt(insockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	/* Bind to udp port */
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
		fprintf(stderr, _("Error binding to %s:%d, %s\n"), inet_ntoa(si_me.sin_addr), sourceport, strerror(errno));
		return 1;
	}

	/* TODO: Move socket initialization out of main() */

	/* Receive mndp udp packets with this socket */
	mndpsockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (mndpsockfd < 0) {
		perror("mndpsockfd");
		return 1;
	}

	memset((char *)&si_me_mndp, 0, sizeof(si_me_mndp));
	si_me_mndp.sin_family = AF_INET;
	si_me_mndp.sin_port = htons(MT_MNDP_PORT);
	memcpy(&(si_me_mndp.sin_addr), &sourceip, IPV4_ALEN);

	setsockopt(mndpsockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	/* Bind to udp port */
	if (bind(mndpsockfd, (struct sockaddr *)&si_me_mndp, sizeof(si_me_mndp)) == -1) {
		fprintf(stderr, _("MNDP: Error binding to %s:%d, %s\n"), inet_ntoa(si_me_mndp.sin_addr), MT_MNDP_PORT,
				strerror(errno));
	}

	openlog("mactelnetd", LOG_PID, LOG_DAEMON);
	syslog(LOG_NOTICE, _("Bound to %s:%d"), inet_ntoa(si_me.sin_addr), sourceport);

	/* Enumerate available interfaces */
	net_get_interfaces(&interfaces);

	setup_sockets();

#if !defined(__APPLE__)
	if (!foreground) {
		daemon(0, 0);
	}
#endif

	/* Handle zombies etc */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGHUP, sighup_handler);
	signal(SIGTERM, sigterm_handler);

	DL_FOREACH(interfaces, interface) {
		if (interface->has_mac) {
			interface_count++;
		}
	}

#if defined(__APPLE__)
	init_network_watcher();
#elif defined(__linux__) && defined(FROM_MACTELNETD) && defined(HAVE_LINUX_NETLINK_H)
	int dfd = get_netlink_fd();
#endif

	if (interface_count == 0) {
		syslog(LOG_ERR, _("Unable to find any valid network interfaces\n"));
		exit(1);
	}

	while (1) {
		int reads;
		struct mt_connection *p, *tmpconn;
		int maxfd = 0;
		time_t now;

		/* Init select */
		FD_ZERO(&read_fds);
		FD_SET(insockfd, &read_fds);
		FD_SET(mndpsockfd, &read_fds);

		maxfd = insockfd > mndpsockfd ? insockfd : mndpsockfd;

#if defined(__linux__) && defined(HAVE_LINUX_NETLINK_H)
		FD_SET(dfd, &read_fds);
		maxfd = dfd > maxfd ? dfd : mndpsockfd;
#endif

		/* Add active connections to select queue */
		DL_FOREACH(connections_head, p) {
			if (p->state == STATE_ACTIVE && p->wait_for_ack == 0 && p->ptsfd > 0) {
				FD_SET(p->ptsfd, &read_fds);
				if (p->ptsfd > maxfd) {
					maxfd = p->ptsfd;
				}
			}
		}

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Wait for data or timeout */
		reads = select(maxfd + 1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
#if defined(__linux__) && defined(HAVE_LINUX_NETLINK_H)
			if (FD_ISSET(dfd, &read_fds)) {
				// Read the netlink socket
				read_netlink(dfd);

				// Debounce
				if (should_refresh_interfaces()) {
					syslog(LOG_NOTICE, _("Network change detected"));
					sighup_handler();
				}
			}
#endif
			if (FD_ISSET(insockfd, &read_fds)) {
				unsigned char buff[MT_PACKET_LEN];
				struct sockaddr_in saddress;
				unsigned int slen = sizeof(saddress);
				bzero(buff, MT_HEADER_LEN);

				result = recvfrom(insockfd, buff, sizeof(buff), 0, (struct sockaddr *)&saddress, &slen);
				handle_packet(buff, result, &saddress);
			}
			if (FD_ISSET(mndpsockfd, &read_fds)) {
				unsigned char buff[MT_PACKET_LEN];
				struct sockaddr_in saddress;
				unsigned int slen = sizeof(saddress);
				result = recvfrom(mndpsockfd, buff, sizeof(buff), 0, (struct sockaddr *)&saddress, &slen);

				/* Handle MNDP broadcast request, max 1 rps */
				if (result == 4 && time(NULL) - last_mndp_time > 0) {
					mndp_broadcast();
					time(&last_mndp_time);
				}
			}
			/* Handle data from terminal sessions */
			DL_FOREACH_SAFE(connections_head, p, tmpconn) {
				/* Check if we have data ready in the pty buffer for the active session */
				if (p->state == STATE_ACTIVE && p->ptsfd > 0 && p->wait_for_ack == 0 && FD_ISSET(p->ptsfd, &read_fds)) {
					unsigned char keydata[1024];
					int datalen, plen;

					/* Read it */
					datalen = read(p->ptsfd, &keydata, sizeof(keydata));
					if (datalen > 0) {
						/* Send it */
						init_packet(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						plen = add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, &keydata, datalen);
						p->outcounter += plen;
						p->wait_for_ack = 1;
						result = send_udp(p, &pdata);
					} else {
						/* Shell exited */
						init_packet(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						send_udp(p, &pdata);
						if (p->username[0] != 0) {
							syslog(LOG_INFO, _("(%d) Connection to user %s closed."), p->seskey, p->username);
						} else {
							syslog(LOG_INFO, _("(%d) Connection closed."), p->seskey);
						}
						list_remove_connection(p);
					}
				} else if (p->state == STATE_ACTIVE && p->ptsfd > 0 && p->wait_for_ack == 1 &&
						   FD_ISSET(p->ptsfd, &read_fds)) {
					printf(_("(%d) Waiting for ack\n"), p->seskey);
				}
			}
			/* Handle select() timeout */
		}
		time(&now);

		if (now - last_mndp_time > MT_MNDP_BROADCAST_INTERVAL) {
			pings = 0;
			mndp_broadcast();
			last_mndp_time = now;
		}
		if (connections_head != NULL) {
			struct mt_connection *p, *tmp;
			DL_FOREACH_SAFE(connections_head, p, tmp) {
				if (now - p->lastdata >= MT_CONNECTION_TIMEOUT) {
					syslog(LOG_INFO, _("(%d) Session timed out"), p->seskey);
					init_packet(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
					/*_ Please include both \r and \n in translation, this is needed for the terminal emulator. */
					add_control_packet(&pdata, MT_CPTYPE_PLAINDATA, _("Timeout\r\n"), 9);
					send_udp(p, &pdata);
					init_packet(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
					send_udp(p, &pdata);

					list_remove_connection(p);
				}
			}
		}
	}

	/* Never reached */
	return 0;
}
