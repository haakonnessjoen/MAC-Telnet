/*
    Mac-Telnet - Connect to RouterOS routers via MAC address
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
#define _XOPEN_SOURCE 600
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <pwd.h>
#include <utmp.h>
#include <syslog.h>
#include "md5.h"
#include "protocol.h"
#include "udp.h"
#include "console.h"
#include "devices.h"
#include "users.h"
#include "config.h"

int sockfd;
int insockfd;
int deviceIndex;

struct in_addr sourceip; 
struct in_addr destip;
int sourceport;

unsigned char trypassword[17];

/* Protocol data direction */
unsigned char mt_direction_fromserver = 1;

/* Anti-timeout is every 10 seconds. Give up after 15. */
#define MT_CONNECTION_TIMEOUT 15

/* Connection states */
#define STATE_AUTH 1
#define STATE_CLOSED 2
#define STATE_ACTIVE 3

/** Connection struct */
struct mt_connection {
	unsigned short seskey;
	unsigned int incounter;
	unsigned int outcounter;
	time_t lastdata;
	int terminalMode;
	unsigned char username[30];
	unsigned char srcip[4];
	unsigned char srcmac[6];
	unsigned short srcport;
	unsigned char dstmac[6];
	unsigned char enckey[16];
	int state;
	int ptsfd;
	int slavefd;
	int pid;
	unsigned short terminal_width;
	unsigned short terminal_height;
	unsigned char terminal_type[30];

	int waitForAck;

	struct mt_connection *next;
};

struct mt_connection *connections_head = NULL;

void list_addConnection(struct mt_connection *conn) {
	struct mt_connection *p;
	struct mt_connection *last;
	if (connections_head == NULL) {
		connections_head = conn;
		connections_head->next = NULL;
		return;
	}
	for (p = connections_head; p != NULL; p = p->next) {last = p;}
	last->next = conn;
	conn->next = NULL;
}

void list_removeConnection(struct mt_connection *conn) {
	struct mt_connection *p;
	struct mt_connection *last;
	if (connections_head == NULL)
		return;

	if (conn->state == STATE_ACTIVE && conn->ptsfd > 0) {
		close(conn->ptsfd);
	}
	if (conn->state == STATE_ACTIVE && conn->slavefd > 0) {
		close(conn->slavefd);
	}


	if (connections_head == conn) {
		connections_head = conn->next;
		free(conn);
		return;
	}

	for (p = connections_head; p != NULL; p = p->next) {
		if (p == conn) {
			last->next = p->next;
			free(p);
			return;
		}
		last = p;
	}
}

struct mt_connection *list_findConnection(unsigned short seskey, unsigned char *srcmac) {
	struct mt_connection *p;

	if (connections_head == NULL)
		return NULL;

	for (p = connections_head; p != NULL; p = p->next) {
		if (p->seskey == seskey && memcmp(srcmac, p->srcmac, 6) == 0) {
			return p;
		}
	}

	return NULL;
}

int sendUDP(const struct mt_connection *conn, const struct mt_packet *data) {
	return sendCustomUDP(sockfd, 2, conn->dstmac, conn->srcmac, &sourceip, sourceport, &destip, conn->srcport, data->data, data->size);
}

void displayMotd() {
	FILE *fp;
	int c;
	
	if ((fp = fopen("/etc/motd", "r"))) {
		while ((c = getc(fp)) != EOF) {
			putchar(c);
		}
		fclose(fp);
	}
}

void displayNologin() {
	FILE *fp;
	int c;
	
	if ((fp = fopen(_PATH_NOLOGIN, "r"))) {
		while ((c = getc(fp)) != EOF) {
			putchar(c);
		}
		fclose(fp);
	}	
}

void adduwtmp(struct mt_connection *curconn) {
	struct utmp utent;
	pid_t pid;

	pid = getpid();
	
	char *line = ttyname(curconn->slavefd);
	if (strncmp(line, "/dev/", 5) == 0)
		line += 5;

	/* Setup utmp struct */
	memset((void *) &utent, 0, sizeof(utent));
	utent.ut_type = USER_PROCESS;
	utent.ut_pid = pid;
	strncpy(utent.ut_user, curconn->username, sizeof(utent.ut_user));
	strncpy(utent.ut_line, line, sizeof(utent.ut_line));
	strncpy(utent.ut_id, utent.ut_line + 3, sizeof(utent.ut_id));
	strncpy(utent.ut_host,ether_ntoa((const struct ether_addr *)curconn->dstmac), sizeof(utent.ut_host));
	time(&utent.ut_time);
	
	/* Update utmp and/or wtmp */
	setutent();
	pututline(&utent);
	endutent();
	updwtmp(_PATH_WTMP, &utent);
}

void abortConnection(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, char *message) {
	struct mt_packet pdata;
	
	initPacket(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, message, strlen(message));
	sendUDP(curconn, &pdata);

	/* Make connection time out; lets the previous message get acked before disconnecting */
	curconn->state = STATE_CLOSED;
	initPacket(&pdata, MT_PTYPE_END, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
	sendUDP(curconn, &pdata);
}

void doLogin(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr) {
	struct mt_packet pdata;
	unsigned char md5sum[17];
	unsigned char md5data[100];
	struct mt_credentials *user;
	char shouldDoLogin = 0;
	char *slavename;

	/* Reparse user file before each login */
	readUserfile();

	if ((user = findUser(curconn->username)) != NULL) {
		md5_state_t state;
		/* Concat string of 0 + password + encryptionkey */
		md5data[0] = 0;
		strncpy(md5data + 1, user->password, 82);
		memcpy(md5data + 1 + strlen(user->password), curconn->enckey, 16);

		/* Generate md5 sum of md5data with a leading 0 */
		md5_init(&state);
		md5_append(&state, (const md5_byte_t *)md5data, strlen(user->password) + 17);
		md5_finish(&state, (md5_byte_t *)md5sum + 1);
		md5sum[0] = 0;

		initPacket(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
		curconn->outcounter += addControlPacket(&pdata, MT_CPTYPE_END_AUTH, NULL, 0);
		sendUDP(curconn, &pdata);

		if (curconn->state == STATE_ACTIVE)
			return;
	}

	if (user != NULL && memcmp(md5sum, trypassword, 17) == 0) {
		curconn->state = STATE_ACTIVE;
	} else {
		syslog(LOG_NOTICE, "(%d) Invalid login by %s.", curconn->seskey, curconn->username);

		abortConnection(curconn, pkthdr, "Login FAILED!\r\n");

		/* TODO: should wait some time (not with sleep) before returning, to minimalize brute force attacks */
		return;
	}

	/* Enter terminal mode */
	curconn->terminalMode = 1;
	
	/* Open pts handle */
	curconn->ptsfd = posix_openpt(O_RDWR);
	if (curconn->ptsfd == -1 || grantpt(curconn->ptsfd) == -1 || unlockpt(curconn->ptsfd) == -1) {
			syslog(LOG_ERR, "posix_openpt: %s", strerror(errno));
			abortConnection(curconn, pkthdr, "Terminal error\r\n");
			return;
	}

	/* Get file path for our pts */
	slavename = ptsname(curconn->ptsfd);
	if (slavename != NULL) {
		pid_t pid;
		struct stat sb;
		
		curconn->slavefd = open(slavename, O_RDWR);
		if (curconn->slavefd == -1) {
			syslog(LOG_ERR, "Error opening %s: %s", slavename, strerror(errno));
			abortConnection(curconn, pkthdr, "Error opening terminal\r\n");
			list_removeConnection(curconn);
			return;
		}

		if ((pid = fork()) == 0) {			
			struct passwd *user = (struct passwd *)getpwnam(curconn->username);
			if (user == NULL) {
				syslog(LOG_WARNING, "(%d) Login ok, but local user not accessible (%s).", curconn->seskey, curconn->username);
				abortConnection(curconn, pkthdr, "Local user not accessible\r\n");
				return;
			}
			
			/* Add login information to utmp/wtmp */
			adduwtmp(curconn);

			syslog(LOG_INFO, "(%d) User %s logged in.", curconn->seskey, curconn->username);

			/* Initialize terminal environment */			
			setenv("USER", user->pw_name, 1);
			setenv("HOME", user->pw_dir, 1);
			setenv("SHELL", user->pw_shell, 1);
			setenv("TERM", curconn->terminal_type, 1);
			close(sockfd);
			close(insockfd);
			setsid();

			/* Don't let shell process inherit slavefd */
			fcntl (curconn->slavefd, F_SETFD, FD_CLOEXEC);
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
				syslog(LOG_ERR, "(%d) Could not log in %s (%d:%d): setuid/setgid: %s", curconn->seskey, curconn->username, user->pw_uid, user->pw_gid, strerror(errno));
				abortConnection(curconn, pkthdr, "Internal error\r\n");
				exit(0);
			}

			/* Abort login if /etc/nologin exists */
			if (stat(_PATH_NOLOGIN, &sb) == 0 && getuid() != 0) {
				syslog(LOG_NOTICE, "(%d) User %s disconnected with " _PATH_NOLOGIN " message.", curconn->seskey, curconn->username);
				displayNologin();
				curconn->state = STATE_CLOSED;
				initPacket(&pdata, MT_PTYPE_END, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
				sendUDP(curconn, &pdata);
				exit(0);
			}

			/* Display MOTD */
			displayMotd();

			/* Spawn shell */
			chdir(user->pw_dir);
			execl(user->pw_shell, user->pw_shell, (char *) 0);
			exit(0); // just to be sure.
		}
		close(curconn->slavefd);
		curconn->pid = pid;
		setTerminalSize(curconn->ptsfd, curconn->terminal_width, curconn->terminal_height);
	}

}

void handleDataPacket(struct mt_connection *curconn, struct mt_mactelnet_hdr *pkthdr, int data_len) {
	struct mt_mactelnet_control_hdr cpkt;
	struct mt_packet pdata;
	unsigned char *data = pkthdr->data;
	int gotUserPacket = 0;
	int gotPassPacket = 0;
	int gotWidthPacket = 0;
	int gotHeightPacket = 0;
	int success;

	/* Parse first control packet */
	success = parseControlPacket(data, data_len - MT_HEADER_LEN, &cpkt);

	while (success) {
		if (cpkt.cptype == MT_CPTYPE_BEGINAUTH) {

			int plen,i;
			for (i = 0; i < 16; ++i) {
				curconn->enckey[i] = rand() % 256;
			}

			initPacket(&pdata, MT_PTYPE_DATA, pkthdr->dstaddr, pkthdr->srcaddr, pkthdr->seskey, curconn->outcounter);
			plen = addControlPacket(&pdata, MT_CPTYPE_ENCRYPTIONKEY, (curconn->enckey), 16);
			curconn->outcounter += plen;

			sendUDP(curconn, &pdata);

			memset(trypassword, 0, sizeof(trypassword));

		} else if (cpkt.cptype == MT_CPTYPE_USERNAME) {

			memcpy(curconn->username, cpkt.data, cpkt.length > 29 ? 29 : cpkt.length);
			curconn->username[cpkt.length > 29 ? 29 : cpkt.length] = 0;
			gotUserPacket = 1;

		} else if (cpkt.cptype == MT_CPTYPE_TERM_WIDTH) {

			curconn->terminal_width = cpkt.data[0] | (cpkt.data[1]<<8);
			gotWidthPacket = 1;

		} else if (cpkt.cptype == MT_CPTYPE_TERM_HEIGHT) {

			curconn->terminal_height = cpkt.data[0] | (cpkt.data[1]<<8);
			gotHeightPacket = 1;

		} else if (cpkt.cptype == MT_CPTYPE_TERM_TYPE) {

			memcpy(curconn->terminal_type, cpkt.data, cpkt.length > 29 ? 29 : cpkt.length);
			curconn->terminal_type[cpkt.length > 29 ? 29 : cpkt.length] = 0;

		} else if (cpkt.cptype == MT_CPTYPE_PASSWORD) {

			memcpy(trypassword, cpkt.data, 17);
			gotPassPacket = 1;

		} else if (cpkt.cptype == MT_CPTYPE_PLAINDATA) {

			/* relay data from client to shell */
			if (curconn->state == STATE_ACTIVE && curconn->ptsfd != -1) {
				write(curconn->ptsfd, cpkt.data, cpkt.length);
			}

		} else {
			syslog(LOG_WARNING, "(%d) Unhandeled control packet type: %d", curconn->seskey, cpkt.cptype);
		}

		/* Parse next control packet */
		success = parseControlPacket(NULL, 0, &cpkt);
	}
	
	if (gotUserPacket && gotPassPacket) {
		doLogin(curconn, pkthdr);
	}
	
	if (curconn->state == STATE_ACTIVE && (gotWidthPacket || gotHeightPacket)) {
		setTerminalSize(curconn->ptsfd, curconn->terminal_width, curconn->terminal_height);

	}
}

void terminate() {
	syslog(LOG_NOTICE, "Exiting.");
	exit(0);
}

void handlePacket(unsigned char *data, int data_len, const struct sockaddr_in *address) {
	struct mt_mactelnet_hdr pkthdr;
	struct mt_connection *curconn;
	struct mt_packet pdata;

	parsePacket(data, &pkthdr);

	switch (pkthdr.ptype) {

		case MT_PTYPE_SESSIONSTART:
			syslog(LOG_DEBUG, "(%d) New connection.", pkthdr.seskey);
			curconn = calloc(1, sizeof(struct mt_connection));
			curconn->seskey = pkthdr.seskey;
			curconn->lastdata = time(NULL);
			curconn->state = STATE_AUTH;
			memcpy(curconn->srcmac, pkthdr.srcaddr, 6);
			memcpy(curconn->srcip, &(address->sin_addr), 4);
			curconn->srcport = htons(address->sin_port);
			memcpy(curconn->dstmac, pkthdr.dstaddr, 6);

			list_addConnection(curconn);

			initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
			sendUDP(curconn, &pdata);
			break;

		case MT_PTYPE_END:
			curconn = list_findConnection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}
			if (curconn->state != STATE_CLOSED) {
				initPacket(&pdata, MT_PTYPE_END, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				sendUDP(curconn, &pdata);
			}
			syslog(LOG_DEBUG, "(%d) Connection closed.", curconn->seskey);
			list_removeConnection(curconn);
			return;

		case MT_PTYPE_ACK:
			curconn = list_findConnection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}
			curconn->lastdata = time(NULL);

			if (pkthdr.counter <= curconn->outcounter) {
				curconn->waitForAck = 0;
			}

			if (pkthdr.counter == curconn->outcounter) {
				// Answer to anti-timeout packet
				/* TODO: only answer if time() - lastpacket is somewhat high.. */
				initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
				sendUDP(curconn, &pdata);
			}
				return;
			break;

		case MT_PTYPE_DATA:
			curconn = list_findConnection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn == NULL) {
				break;
			}
			curconn->lastdata = time(NULL);

			/* ack the data packet */
			initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter + (data_len - MT_HEADER_LEN));
			sendUDP(curconn, &pdata);

			/* Accept first packet, and all packets greater than incounter, and if counter has
			wrapped around. */
			if (curconn->incounter == 0 || pkthdr.counter > curconn->incounter || (curconn->incounter - pkthdr.counter) > 16777216) {
				curconn->incounter = pkthdr.counter;
			} else {
				/* Ignore double or old packets */
				return;
			}

			handleDataPacket(curconn, &pkthdr, data_len);
			break;
		default:
			syslog(LOG_WARNING, "(%d) Unhandeled packet type: %d", curconn->seskey, pkthdr.ptype);
			initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
			sendUDP(curconn, &pdata);
	}
	if (0 && curconn != NULL) {
		printf("Packet, incounter %d, outcounter %d\n", curconn->incounter, curconn->outcounter);
	}
}

void daemonize() {
	int pid,fd;

	pid = fork();

	/* Error? */
	if (pid < 0)
		exit(1);

	/* Parent exit */
	if (pid > 0)
		exit(0);

	setsid();
	close(0);
	close(1);
	close(2);
	
	fd = open("/dev/null",O_RDWR);
	dup(fd);
	dup(fd);

	signal(SIGCHLD,SIG_IGN);
	signal(SIGTSTP,SIG_IGN);
	signal(SIGTTOU,SIG_IGN);
	signal(SIGTTIN,SIG_IGN);	
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int result;
	struct sockaddr_in si_me;
	struct timeval timeout;
	int keepalive_counter = 0;
	struct mt_packet pdata;
	fd_set read_fds;

	/* Try to read user file */
	readUserfile();

	/* Seed randomizer */
	srand(time(NULL));

	if (geteuid() != 0) {
		fprintf(stderr, "You need to have root privileges to use %s.\n", argv[0]);
		return 1;
	}

	/* Transmit raw packets with this socket */
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd < 0) {
		perror("sockfd");
		return 1;
	}

	/* Receive regular udp packets with this socket */
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (insockfd < 0) {
		perror("insockfd");
		return 1;
	}

	/* Set random source port */
	sourceport = MT_MACTELNET_PORT;

	/* Listen address*/
	inet_pton(AF_INET, (char *)"0.0.0.0", &sourceip);

	/* Set up global info about the connection */
	inet_pton(AF_INET, (char *)"255.255.255.255", &destip);

	/* Initialize receiving socket on the device chosen */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(MT_MACTELNET_PORT);
	memcpy(&(si_me.sin_addr), &sourceip, 4);

	/* Bind to udp port */
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to %s:%d, %s\n", inet_ntoa(si_me.sin_addr), sourceport, strerror(errno));
		return 1;
	}

	daemonize();
	openlog("mactelnetd", LOG_PID, LOG_DAEMON);
	
	syslog(LOG_NOTICE, "Bound to %s:%d", inet_ntoa(si_me.sin_addr), sourceport);
	
	signal(SIGTERM, terminate);
	
	while (1) {
		int reads;
		struct mt_connection *p;
		int maxfd=0;

		/* Init select */
		FD_ZERO(&read_fds);
		FD_SET(insockfd, &read_fds);
		maxfd = sockfd > insockfd ? sockfd : insockfd;

		/* Add active connections to select queue */
		for (p = connections_head; p != NULL; p = p->next) {
			if (p->state == STATE_ACTIVE && p->waitForAck == 0 && p->ptsfd > 0) {
				FD_SET(p->ptsfd, &read_fds);
				if (p->ptsfd > maxfd)
					maxfd = p->ptsfd;
			}
		}

		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;

		/* Wait for data or timeout */
		reads = select(maxfd+1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
			/* Handle data from clients
			 TODO: Check if packet is for us. And enable broadcast support (without raw sockets)
			 */
			if (FD_ISSET(insockfd, &read_fds)) {
				unsigned char buff[1500];
				struct sockaddr_in saddress;
				int slen = sizeof(saddress);
				result = recvfrom(insockfd, buff, 1500, 0, (struct sockaddr *)&saddress, &slen);
				handlePacket(buff, result, &saddress);
			}
			/* Handle data from terminal sessions */
			for (p = connections_head; p != NULL; p = p->next) {
				/* Check if we have data ready in the pty buffer for the active session */
				if (p->state == STATE_ACTIVE && p->ptsfd > 0 && p->waitForAck == 0 && FD_ISSET(p->ptsfd, &read_fds)) {
					unsigned char keydata[1024];
					int datalen,plen;

					/* Read it */
					datalen = read(p->ptsfd, &keydata, 1024);
					if (datalen != -1) {
						/* Send it */
						initPacket(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						plen = addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, &keydata, datalen);
						p->outcounter += plen;
						p->waitForAck = 1;
						result = sendUDP(p, &pdata);
					} else {
						/* Shell exited */
						struct mt_connection tmp;
						initPacket(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						sendUDP(p, &pdata);
						if (p->username != NULL) {
							syslog(LOG_INFO, "(%d) Connection to user %s closed.", p->seskey, p->username);
						} else {
							syslog(LOG_INFO, "(%d) Connection closed.", p->seskey);
						}
						tmp.next = p->next;
						list_removeConnection(p);
						p = &tmp;
					}
				}
				else if (p->state == STATE_ACTIVE && p->ptsfd > 0 && p->waitForAck == 1 && FD_ISSET(p->ptsfd, &read_fds)) {
					printf("(%d) Waiting for ack\n", p->seskey);
				}
			}
		/* Handle select() timeout */
		} else {
			if (connections_head != NULL) {
				struct mt_connection *p,tmp;
				for (p = connections_head; p != NULL; p = p->next) {
					if (time(NULL) - p->lastdata >= MT_CONNECTION_TIMEOUT) {
						syslog(LOG_INFO, "(%d) Session timed out", p->seskey);
						initPacket(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, "Timeout\r\n", 9);
						sendUDP(p, &pdata);
						initPacket(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						sendUDP(p, &pdata);

						tmp.next = p->next;
						list_removeConnection(p);
						p = &tmp;
					}
				}
			}
		}
	}

	close(sockfd);
	close(insockfd);
	closelog();
	return 0;
}
