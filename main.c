/*
    Mac-Telnet - Connect to RouterOS clients via MAC address
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
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include <openssl/md5.h>
#include "mactelnet.h"
#include "udp.h"
#include "console.h"
#include "config.h"

int sockfd;
int counter=0;
int outcounter=0;
int sessionkey=0;
unsigned char *src = "00:e0:81:b5:ac:8e";
unsigned char *dst = "00:0c:42:43:58:a4";
unsigned char encryptionkey[128];

void handlePacket(unsigned char *data, int data_len) {
	struct mt_mactelnet_hdr pkthdr;
	struct mt_mactelnet_control_hdr cpkthdr;
	parsePacket(data, &pkthdr);

	if (DEBUG)
		printf("Received packet:\n\tVersion %d\n\tType: %d\n\tSesskey: %d\n\tCounter: %d\n\n", pkthdr.ver, pkthdr.ptype, pkthdr.seskey, pkthdr.counter);

	if (pkthdr.ptype == MT_PTYPE_DATA) {
		char odata[200];
		int plen=0,result=0;
		int rest = 0;
		unsigned char *p = data;
		counter += data_len - 22;
		plen = initPacket(odata, MT_PTYPE_ACK, src, dst, pkthdr.seskey, counter);
		result = sendCustomUDP(sockfd, src, dst, "213.236.240.252", 20561, "255.255.255.255", 20561, odata, plen);

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
				strcpy(md5data+1, "password");
				strncat(md5data+1, encryptionkey, 16);

				MD5_Init(&c);
				MD5_Update(&c, md5data, 9+16);
				MD5_Final(md5sum+1, &c);
				md5sum[0] = 0;

				sendAuthData("admin", md5sum);
				if (DEBUG)
					printf("Received encryption key of %d characters\n", cpkt.length);
				
			}
			else if (cpkt.cptype == MT_CPTYPE_PLAINDATA) {
				cpkt.data[cpkt.length] = 0;
				printf("%s", cpkt.data);
			}
		}
	}
}

void sendAuthData(unsigned char *username, unsigned char *password) {
	unsigned char data[1500];
	unsigned char *terminal = "linux";
	int userLen = strlen(username);
	int terminalLen = strlen(terminal);
	unsigned short width = 0;
	unsigned short height = 0;
	int result;
	int plen;
	int databytes;

	plen = initPacket(data, MT_PTYPE_DATA, src, dst, sessionkey, outcounter);
	databytes = plen;
	plen += addControlPacket(data + plen, MT_CPTYPE_PASSWORD, password, 17);
	plen += addControlPacket(data + plen, MT_CPTYPE_USERNAME, username, userLen);
	plen += addControlPacket(data + plen, MT_CPTYPE_TERM_TYPE, terminal, terminalLen);

	if (getTerminalSize(&width, &height) > 0) {
		plen += addControlPacket(data + plen, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += addControlPacket(data + plen, MT_CPTYPE_TERM_HEIGHT, &height, 2);
	}

	outcounter += plen - databytes;

	result = sendCustomUDP(sockfd, src, dst, "213.236.240.252", 20561, "255.255.255.255", 20561, data, plen);
}

int main (int argc, char **argv) {
	int insockfd;
	int result;
	char data[200];
	struct sockaddr_in si_me;
	char buff[1500];
	int plen = 0;

	srand(time(NULL));

	// Transmit raw packets with this socket
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	// Receive regular udp packets with this socket
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// Initialize receiving socket
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(20561);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	// Bind to udp port
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to port 20561\n");
		return 1;
	}

	// Sessioon key
	sessionkey = rand() % 65535;

	printf("Connecting to %s...\n", dst);

	plen = initPacket(data, MT_PTYPE_SESSIONSTART, src, dst, sessionkey, 0);
	result = sendCustomUDP(sockfd, src, dst, "213.236.240.252", 20561, "255.255.255.255", 20561, data, plen);
	if (DEBUG)
		printf("Plen = %d, Send result: %d\n", plen, result);
	if (DEBUG)
		printf("Sessionkey: %d\n", sessionkey);

	result = recvfrom(insockfd, buff, 1400, 0, 0, 0);
	handlePacket(buff, result);

	// TODO: Should resubmit whenever a PTYPE_DATA packet is sent, and an ACK packet with correct datacounter is received
	// or time out the connection, in all other cases.
	plen = initPacket(data, MT_PTYPE_DATA, src, dst, sessionkey, 0);
	plen += addControlPacket(data + plen, MT_CPTYPE_BEGINAUTH, NULL, 0);
	outcounter += 9;

	result = sendCustomUDP(sockfd, src, dst, "213.236.240.252", 20561, "255.255.255.255", 20561, data, plen);
	if (DEBUG)
		printf("Plen = %d, Send result: %d\n", plen, result);

	memset(buff, 0, 1500);
	result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
	if (result < 1) {
		fprintf(stderr, "Connection failed.\n");
		return 1;
	}
	handlePacket(buff, result);

	memset(buff, 0, 1500);
	result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
	handlePacket(buff, result);

	memset(buff, 0, 1500);
	result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
	handlePacket(buff, result);

	memset(buff, 0, 1500);
	result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
	handlePacket(buff, result);

while(1) {
	memset(buff, 0, 1500);
	result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
	handlePacket(buff, result);
}
	close(sockfd);
	close(insockfd);

	return 0;
}
