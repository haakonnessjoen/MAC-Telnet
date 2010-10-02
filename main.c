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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
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
#include "mactelnet.h"
#include "udp.h"
#include "console.h"
#include "devices.h"
#include "config.h"

int sockfd;
int deviceIndex;
int outcounter=0;
int sessionkey=0;
int running = 1;

unsigned char terminalMode = 0;

unsigned char srcmac[ETH_ALEN];
unsigned char dstmac[ETH_ALEN];

struct in_addr sourceip; 
struct in_addr destip;
int sourceport;

unsigned char encryptionkey[128];
unsigned char username[255];
unsigned char password[255];

int sendUDP(const unsigned char *data, int len) {
	return sendCustomUDP(sockfd, deviceIndex, srcmac, dstmac, &sourceip,  sourceport, &destip, 20561, data, len);
}

void sendAuthData(unsigned char *username, unsigned char *password) {
	unsigned char data[1500];
	unsigned char *terminal = getenv("TERM");
	int userLen = strlen(username);
	int terminalLen = strlen(terminal);
	unsigned short width = 0;
	unsigned short height = 0;
	int result;
	int plen;
	int databytes;

	plen = initPacket(data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
	databytes = plen;
	plen += addControlPacket(data + plen, MT_CPTYPE_PASSWORD, password, 17);
	plen += addControlPacket(data + plen, MT_CPTYPE_USERNAME, username, userLen);
	plen += addControlPacket(data + plen, MT_CPTYPE_TERM_TYPE, terminal, terminalLen);

	if (getTerminalSize(&width, &height) > 0) {
		plen += addControlPacket(data + plen, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += addControlPacket(data + plen, MT_CPTYPE_TERM_HEIGHT, &height, 2);
	}

	outcounter += plen - databytes;

	result = sendUDP(data, plen);
}

void sig_winch(int sig) {
	unsigned short width,height;
	unsigned char data[1500];
	int result,plen,databytes;

	if (getTerminalSize(&width, &height) > 0) {
		plen = initPacket(data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
		databytes = plen;
		plen += addControlPacket(data + plen, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += addControlPacket(data + plen, MT_CPTYPE_TERM_HEIGHT, &height, 2);
		outcounter += plen - databytes;

		result = sendUDP(data, plen);
	}
	signal(SIGWINCH, sig_winch);
}

void handlePacket(unsigned char *data, int data_len) {
	struct mt_mactelnet_hdr pkthdr;
	parsePacket(data, &pkthdr);

	if (DEBUG)
		printf("Received packet:\n\tVersion %d\n\tType: %d\n\tSesskey: %d\n\tCounter: %d\n\n", pkthdr.ver, pkthdr.ptype, pkthdr.seskey, pkthdr.counter);

	if (pkthdr.seskey != sessionkey) {
		if (DEBUG)
			fprintf(stderr, "Invalid session key in received packet.\n");
		return;
	}

	if (pkthdr.ptype == MT_PTYPE_DATA) {
		char odata[200];
		int plen=0,result=0;
		int rest = 0;
		unsigned char *p = data;
		plen = initPacket(odata, MT_PTYPE_ACK, srcmac, dstmac, sessionkey, pkthdr.counter + (data_len - 22));
		result = sendUDP(odata, plen);

		if (DEBUG)
			printf("ACK: Plen = %d, Send result: %d\n", plen, result);

		rest = data_len - 22;
		p += 22;
		while (rest > 0) {
			int read = 0;
			struct mt_mactelnet_control_hdr cpkt;
			read = parseControlPacket(p, rest, &cpkt);
			p += read;
			rest -= read;

			if (cpkt.cptype == MT_CPTYPE_ENCRYPTIONKEY) {
				unsigned char md5data[100];
				unsigned char md5sum[100];
				MD5_CTX c;

				memcpy(encryptionkey, cpkt.data, cpkt.length);

				md5data[0] = 0;
				strcpy(md5data+1, password);
				strncat(md5data+1, encryptionkey, 16);

				MD5_Init(&c);
				MD5_Update(&c, md5data, 9+16);
				MD5_Final(md5sum+1, &c);
				md5sum[0] = 0;

				sendAuthData(username, md5sum);
				if (DEBUG)
					printf("Received encryption key of %d characters\n", cpkt.length);
				
			}
		
			else if (cpkt.cptype == MT_CPTYPE_PLAINDATA) {
				cpkt.data[cpkt.length] = 0;
				printf("%s", cpkt.data);
			}

			else if (cpkt.cptype == MT_CPTYPE_END_AUTH) {
				terminalMode = 1;
				signal(SIGWINCH, sig_winch);
			}
		}
	}
	else if (pkthdr.ptype == MT_PTYPE_ACK) {
		/* TODO: If we were resubmitting lost messages, stop resubmitting here if received counter is correct. */
	}
	else if (pkthdr.ptype == MT_PTYPE_END) {
		char odata[200];
		int plen=0,result=0;
		plen = initPacket(odata, MT_PTYPE_END, srcmac, dstmac, pkthdr.seskey, 0);
		result = sendUDP(odata, plen);
		fprintf(stderr, "Connection closed.\n");
		/* exit */
		running = 0;
	} else {
		fprintf(stderr, "Unhandeled packet type: %d received from server %s\n", pkthdr.ptype, ether_ntoa((struct ether_addr *)dstmac));
	}
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int insockfd;
	int result;
	char data[1500];
	struct sockaddr_in si_me;
	char buff[1500];
	int plen = 0;
	struct timeval timeout;
	int keepalive_counter = 0;
	fd_set read_fds;

	if (argc < 4) {
		fprintf(stderr, "Usage: %s <ifname> <MAC> <username> [password]\n", argv[0]);

		if (argc > 1) {
			fprintf(stderr, "\nParameters:\n");
			fprintf(stderr, "  ifname    Network interface that the RouterOS resides on. (example: eth0)\n");
			fprintf(stderr, "  MAC       MAC-Address of the RouterOS device. Use mndp to discover them.\n");
			fprintf(stderr, "  username  Your username.\n");
			fprintf(stderr, "  password  Your password.\n");
		}
		return 1;
	} else if (argc == 4) {
		char *tmp;
		tmp = getpass("Passsword: ");
		strncpy(password, tmp, 254);
		/* security */
		memset(tmp, 0, strlen(tmp));
	} else {
		strncpy(password, argv[4], 254);
	}

	ether_aton_r(argv[2], (struct ether_addr *)dstmac);
	strncpy(username, argv[3], 254);

	srand(time(NULL));

	/* Transmit raw packets with this socket */
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	/* Receive regular udp packets with this socket */
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	deviceIndex = getDeviceIndex(sockfd, argv[1]);
	if (deviceIndex < 0) {
		fprintf(stderr, "Device %s not found.\n", argv[1]);
		return 1;
	}

	/*
	 * We want to show who we are (ip), even though the server only cares
	 * about it's own MAC address in the headers.
	*/
	result = getDeviceIp(sockfd, argv[1], &si_me);
	if (result < 0) {
		fprintf(stderr, "Cannot determine IP of device %s\n", argv[1]);
		return 1;
	}

	/* Determine source mac address */
	result = getDeviceMAC(sockfd, argv[1], srcmac);
	if (result < 0) {
		fprintf(stderr, "Cannot determine MAC address of device %s\n", argv[1]);
		return 1;
	}

	/* Set source port */
	sourceport = 1024 + (rand() % 1024);

	/* Set up global info about the connection */
	inet_pton(AF_INET, (char *)"255.255.255.255", &destip);
	memcpy(&sourceip, &(si_me.sin_addr), 4);

	/* Initialize receiving socket on the device chosen */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(sourceport);

	/* Bind to udp port */
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to %s:%d\n", inet_ntoa(si_me.sin_addr), sourceport);
		return 1;
	}

	/* Sessioon key */
	sessionkey = rand() % 65535;

	/* stop output buffering */
	setvbuf(stdout, (char*)NULL, _IONBF, 0);

	printf("Connecting to %s...", ether_ntoa((struct ether_addr *)dstmac));

	plen = initPacket(data, MT_PTYPE_SESSIONSTART, srcmac, dstmac, sessionkey, 0);
	result = sendUDP(data, plen);
	if (DEBUG)
		printf("Plen = %d, Send result: %d\n", plen, result);
	if (DEBUG)
		printf("Sessionkey: %d\n", sessionkey);

	FD_ZERO(&read_fds);
	FD_SET(insockfd, &read_fds);
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	select(insockfd+1, &read_fds, NULL, NULL, &timeout);

	if (!FD_ISSET(insockfd, &read_fds)) {
		fprintf(stderr, "Connection timed out\n");
		exit(1);
	}

	result = recvfrom(insockfd, buff, 1400, 0, 0, 0);
	printf("done\n");

	handlePacket(buff, result);

	/*
	 * TODO: Should resubmit whenever a PTYPE_DATA packet is sent, and an ACK packet with correct datacounter is received
	 * or time out the connection, in all other cases.
	*/
	plen = initPacket(data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, 0);
	plen += addControlPacket(data + plen, MT_CPTYPE_BEGINAUTH, NULL, 0);
	outcounter += 9;

	result = sendUDP(data, plen);
	if (DEBUG)
		printf("Plen = %d, Send result: %d\n", plen, result);

	memset(buff, 0, 1500);
	result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
	if (result < 1) {
		fprintf(stderr, "Connection failed.\n");
		return 1;
	}
	handlePacket(buff, result);

	/* stop input buffering at all levels. Give full control of terminal to RouterOS */
	rawTerm();
	setvbuf(stdin,  (char*)NULL, _IONBF, 0);

	while (running) {
		int reads;

		FD_ZERO(&read_fds);
		FD_SET(0, &read_fds);
		FD_SET(insockfd, &read_fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		reads = select(insockfd+1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
			if (FD_ISSET(insockfd, &read_fds)) {
				memset(buff, 0, 1500);
				result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
				handlePacket(buff, result);
			}
			if (FD_ISSET(0, &read_fds)) {
				unsigned char keydata[100];
				int datalen;
				datalen = read(STDIN_FILENO, &keydata, 100);
				memset(data, 0, sizeof(data));
				plen = initPacket(data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
				outcounter += datalen;
				memcpy(data + plen, &keydata, datalen);
				result = sendUDP(data, plen + datalen);
			}
		} else {
			/* keepalive */
			if ((keepalive_counter++ % 10) == 0) {
				char odata[22];
				int plen=0,result=0;
				plen = initPacket(odata, MT_PTYPE_ACK, srcmac, dstmac, sessionkey, 0);
				result = sendUDP(odata, plen);
			}
		}
	}
	resetTerm();
	close(sockfd);
	close(insockfd);

	return 0;
}
