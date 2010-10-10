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
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include <openssl/md5.h>
#include <pwd.h>
#include <sys/ioctl.h>
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

struct mt_connection {
	unsigned short seskey;
	unsigned short incounter;
	unsigned short outcounter;
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

	struct mt_connection *next;
};

struct mt_connection *connections_head = NULL;

void addConnection(struct mt_connection *conn) {
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

void removeConnection(struct mt_connection *conn) {
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

struct mt_connection *findConnection(unsigned short seskey, unsigned char *srcmac) {
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

void handlePacket(unsigned char *data, int data_len, const struct sockaddr_in *address) {
	struct mt_mactelnet_hdr pkthdr;
	struct mt_connection *curconn;
	struct mt_packet pdata;

	parsePacket(data, &pkthdr);

	switch (pkthdr.ptype) {

		case MT_PTYPE_SESSIONSTART:
			printf("Adding connection with sessionid %d\n", pkthdr.seskey);
			curconn = calloc(1, sizeof(struct mt_connection));
			curconn->seskey = pkthdr.seskey;
			curconn->lastdata = time(NULL);
			curconn->state = STATE_AUTH;
			memcpy(curconn->srcmac, pkthdr.srcaddr, 6);
			memcpy(curconn->srcip, &(address->sin_addr), 4);
			curconn->srcport = htons(address->sin_port);
			memcpy(curconn->dstmac, pkthdr.dstaddr, 6);

			addConnection(curconn);

			initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
			sendUDP(curconn, &pdata);
			break;

		case MT_PTYPE_END:
			curconn = findConnection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn != NULL) {
				if (curconn->state != STATE_CLOSED) {
					initPacket(&pdata, MT_PTYPE_END, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
					sendUDP(curconn, &pdata);
				}
				printf("Connection with sessionid %d closed.\n", curconn->seskey);
				removeConnection(curconn);
				return;
			}
			break;

		case MT_PTYPE_ACK:
			curconn = findConnection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn != NULL) {
				curconn->lastdata = time(NULL);
				if (pkthdr.counter == curconn->outcounter) {
					// Answer to anti-timeout packet
					initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
					sendUDP(curconn, &pdata);
				}
				return;
			}
			break;

		case MT_PTYPE_DATA:
			curconn = findConnection(pkthdr.seskey, (unsigned char *)&(pkthdr.srcaddr));
			if (curconn != NULL) {
				unsigned char *p = data;
				int rest;
				char doLogin = 0;

				curconn->lastdata = time(NULL);

				/* ack the data packet */
				initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter + (data_len - MT_HEADER_LEN));
				sendUDP(curconn, &pdata);

				/* Calculate how much more there is in the packet */
				rest = data_len - MT_HEADER_LEN;
				p += MT_HEADER_LEN;

				while (rest > 0) {
					int read;
					struct mt_mactelnet_control_hdr cpkt;

					/* Parse controlpacket data */
					read = parseControlPacket(p, rest, &cpkt);
					p += read;
					rest -= read;

					//read = parseControlPacket(data+22, data_len-22, &cpkt);

					if (cpkt.cptype == MT_CPTYPE_BEGINAUTH) {
						int plen,i;
						for (i = 0; i < 16; ++i) {
							curconn->enckey[i] = rand() % 256;
						}
						initPacket(&pdata, MT_PTYPE_DATA, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
						plen = addControlPacket(&pdata, MT_CPTYPE_ENCRYPTIONKEY, (curconn->enckey), 16);
						curconn->outcounter = plen;
						sendUDP(curconn, &pdata);
						memset(trypassword, 0, sizeof(trypassword));

					} else if (cpkt.cptype == MT_CPTYPE_USERNAME) {

						memcpy(curconn->username, cpkt.data, cpkt.length > 29 ? 29 : cpkt.length);
						curconn->username[cpkt.length > 29 ? 29 : cpkt.length] = 0;

					} else if (cpkt.cptype == MT_CPTYPE_TERM_WIDTH) {

						curconn->terminal_width = cpkt.data[0] | (cpkt.data[1]<<8);
						if (curconn->state == STATE_ACTIVE) {
							setTerminalSize(curconn->ptsfd, curconn->terminal_width, curconn->terminal_height);
						}

					} else if (cpkt.cptype == MT_CPTYPE_TERM_HEIGHT) {

						curconn->terminal_height = cpkt.data[0] | (cpkt.data[1]<<8);
						if (curconn->state == STATE_ACTIVE) {
							setTerminalSize(curconn->ptsfd, curconn->terminal_width, curconn->terminal_height);
						}

					} else if (cpkt.cptype == MT_CPTYPE_TERM_TYPE) {

						memcpy(curconn->terminal_type, cpkt.data, cpkt.length > 29 ? 29 : cpkt.length);
						curconn->terminal_type[cpkt.length > 29 ? 29 : cpkt.length] = 0;

					} else if (cpkt.cptype == MT_CPTYPE_PASSWORD) {

						memcpy(trypassword, cpkt.data, 17);
						doLogin = 1;

					} else if (cpkt.cptype == MT_CPTYPE_PLAINDATA) {
						if (curconn->state == STATE_ACTIVE && curconn->ptsfd != -1) {
							write(curconn->ptsfd, cpkt.data, cpkt.length);
						}
					} else {
						printf("Unhandeled CPTYPE: %d\n", cpkt.cptype);
					}
				}
				if (doLogin) {
						int plen = 0;
						unsigned char md5sum[17];
						unsigned char md5data[100];
						struct mt_credentials *user;

						readUserfile();

						if ((user = findUser(curconn->username)) != NULL) {
							MD5_CTX c;
							/* Concat string of 0 + password + encryptionkey */
							md5data[0] = 0;
							strncpy(md5data + 1, user->password, 82);
							memcpy(md5data + 1 + strlen(user->password), curconn->enckey, 16);

							/* Generate md5 sum of md5data with a leading 0 */
							MD5_Init(&c);
							MD5_Update(&c, md5data, strlen(user->password) + 17);
							MD5_Final(md5sum + 1, &c);
							md5sum[0] = 0;

							initPacket(&pdata, MT_PTYPE_DATA, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
							plen = addControlPacket(&pdata, MT_CPTYPE_END_AUTH, NULL, 0);
							curconn->outcounter += plen;
							sendUDP(curconn, &pdata);

							if (curconn->state == STATE_ACTIVE)
								return;
						} else {
							doLogin = 0;
						}

						if (doLogin == 1 && memcmp(md5sum, trypassword, 17) == 0) {
							initPacket(&pdata, MT_PTYPE_DATA, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
							plen = addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, "Login OK!\r\n", 11);
							sendUDP(curconn, &pdata);
							curconn->outcounter += plen;
							curconn->state = STATE_ACTIVE;
							curconn->terminalMode = 1;
						} else {
							initPacket(&pdata, MT_PTYPE_DATA, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
							plen = addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, "Login FAILED!\r\n", 15);
							sendUDP(curconn, &pdata);
							curconn->outcounter += plen;
							curconn->state = STATE_CLOSED;
							initPacket(&pdata, MT_PTYPE_END, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
							sendUDP(curconn, &pdata);
							/* TODO: should wait some time (not with sleep) before returning, to minimalize brute force attacks */
							return;
					}

					char *slavename;
					curconn->ptsfd = posix_openpt(O_RDWR);
					if (curconn->ptsfd == -1 || grantpt(curconn->ptsfd) == -1 || unlockpt(curconn->ptsfd) == -1) {
							perror("openpt");
							initPacket(&pdata, MT_PTYPE_DATA, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
							addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, "Terminal error\r\n", 15);
							sendUDP(curconn, &pdata);
							curconn->state = STATE_CLOSED;
							initPacket(&pdata, MT_PTYPE_END, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
							sendUDP(curconn, &pdata);
							return;
					}
					slavename = ptsname(curconn->ptsfd);
					if (slavename != NULL) {
						int pid;
						curconn->slavefd = open(slavename, O_RDWR);
						if (curconn->slavefd == -1) {
							perror ("Error opening the slave");
							removeConnection(curconn);
							return;
						}
						fcntl (curconn->slavefd, F_SETFD, FD_CLOEXEC);
						if ((pid = fork()) == 0) {
							struct passwd *user = (struct passwd *)getpwnam(curconn->username);
							if (user == NULL) {
								initPacket(&pdata, MT_PTYPE_DATA, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
								addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, "User not found\r\n", 16);
								sendUDP(curconn, &pdata);
								curconn->state = STATE_CLOSED;
								initPacket(&pdata, MT_PTYPE_END, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, curconn->outcounter);
								sendUDP(curconn, &pdata);
								return;
							}
							setuid(user->pw_uid);
							setgid(user->pw_gid);
							setenv("USER", user->pw_name,1);
							setenv("HOME", user->pw_dir, 1);
							setenv("SHELL", user->pw_shell, 1);
							setenv("TERM", curconn->terminal_type, 1);
							close(sockfd);
							close(insockfd);
							setsid();
							close(0);
							dup(curconn->slavefd);
							close(1);
							dup(curconn->slavefd);
							close(2);
							dup(curconn->slavefd);
							close(curconn->ptsfd);
							/* Set controlling terminal */
							ioctl (0, TIOCSCTTY, 1);
							close(curconn->slavefd);
							chdir(user->pw_dir);
							/* Spawn shell */
							execl (user->pw_shell, user->pw_shell, (char *) 0);
							//exit(0);
						}
						close(curconn->slavefd);
						curconn->pid = pid;
						setTerminalSize(curconn->ptsfd, curconn->terminal_width, curconn->terminal_height);
					}
				}
			}
			break;

		default:
			printf("Unhandeled packet type: %d\n", pkthdr.ptype);
			initPacket(&pdata, MT_PTYPE_ACK, pkthdr.dstaddr, pkthdr.srcaddr, pkthdr.seskey, pkthdr.counter);
			sendUDP(curconn, &pdata);
	}
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

	printf("Bound to %s:%d\n", inet_ntoa(si_me.sin_addr), sourceport);

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
			if (p->state == STATE_ACTIVE && p->ptsfd > 0) {
				FD_SET(p->ptsfd, &read_fds);
				if (p->ptsfd > maxfd)
					maxfd = p->ptsfd;
			}
		}

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Wait for data or timeout */
		reads = select(maxfd+1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
			/* Handle data from clients */
			if (FD_ISSET(insockfd, &read_fds)) {
				unsigned char buff[1500];
				struct sockaddr_in saddress;
				int slen = sizeof(saddress);
				result = recvfrom(insockfd, buff, 1500, 0, (struct sockaddr *)&saddress, &slen);
				handlePacket(buff, result, &saddress);
			}

			for (p = connections_head; p != NULL; p = p->next) {
				/* Check if we have data ready in the pty buffer for the active session */
				if (p->state == STATE_ACTIVE && p->ptsfd > 0 && FD_ISSET(p->ptsfd, &read_fds)) {
					unsigned char keydata[100];
					int datalen,plen;

					/* Read it */
					datalen = read(p->ptsfd, &keydata, 100);
					if (datalen != -1) {
						/* Send it */
						initPacket(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						plen = addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, &keydata, datalen);
						p->outcounter += plen;
						result = sendUDP(p, &pdata);
					} else {
						/* Bash exited */
						initPacket(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						sendUDP(p, &pdata);
						printf("Connection with sessionid %d closed.\n", p->seskey);
						removeConnection(p);
					}
				}
			}
		/* Handle select() timeout */
		} else {
			/* TODO: Kill timed out sessions */
			if (connections_head != NULL) {
				struct mt_connection *p;
				for (p = connections_head; p != NULL; p = p->next) {
					if (time(NULL) - p->lastdata >= MT_CONNECTION_TIMEOUT) {
						printf("Sessionid %d timed out\n", p->seskey);
						initPacket(&pdata, MT_PTYPE_DATA, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						addControlPacket(&pdata, MT_CPTYPE_PLAINDATA, "Timeout\r\n", 9);
						sendUDP(p, &pdata);
						initPacket(&pdata, MT_PTYPE_END, p->dstmac, p->srcmac, p->seskey, p->outcounter);
						sendUDP(p, &pdata);
						removeConnection(p);
						//break;
					}
				}
			}
		}
	}

	close(sockfd);
	close(insockfd);

	return 0;
}
