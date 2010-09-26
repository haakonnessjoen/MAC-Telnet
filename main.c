#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include "udp.h"

#define DEBUG 0

#define MT_PTYPE_SESSIONSTART 0
#define MT_PTYPE_DATA 1
#define MT_PTYPE_ACK 2
#define MT_PTYPE_END 255

#define MT_CPTYPE_BEGINAUTH 0
#define MT_CPTYPE_ENCRYPTIONKEY 1
#define MT_CPTYPE_PASSWORD 2
#define MT_CPTYPE_USERNAME 3
#define MT_CPTYPE_TERM_TYPE 4
#define MT_CPTYPE_TERM_WIDTH 5
#define MT_CPTYPE_TERM_HEIGHT 6
#define MT_CPTYPE_PACKET_ERROR 7
#define MT_CPTYPE_END_AUTH 9

int initPacket(unsigned char *data, unsigned char ptype, unsigned char *src, unsigned char *dst, unsigned short sessionkey, unsigned short counter) {

	// PACKET VERSION
	data[0] = 1;

	// PACKET TYPE
	data[1] = ptype;

	// src ethernet address
	etherAddrton(data + 2, src);

	// dst ethernet address
	etherAddrton(data + 8, dst);

	data[14] = sessionkey >> 8;
	data[15] = sessionkey & 0xff;

	data[16] = 0x00;
	data[17] = 0x15;

	data[18] = (counter >> 24) & 0xff;
	data[19] = (counter >> 16) & 0xff;
	data[20] = (counter >> 8) & 0xff;
	data[21] = counter & 0xff;

	return 22;
}

int addControlPacket(unsigned char *data, unsigned char cptype, unsigned char *cpdata, int data_len) {
	data[0] = 0x56;
	data[1] = 0x34;
	data[2] = 0x12;
	data[3] = 0xff;

	// Control packet type
	data[4] = cptype;

	// Data length
	data[5] = (data_len >> 24) & 0xff;
	data[6] = (data_len >> 16) & 0xff;
	data[7] = (data_len >> 8) & 0xff;
	data[8] = data_len & 0xff;

	if (data_len) {
		memcpy(data+9, cpdata, data_len);
	}

	return 9+data_len;
}

struct mt_mactelnet_hdr {
	unsigned char ver;
	unsigned char ptype;
	unsigned char srcaddr[6];
	unsigned char dstaddr[6];
	unsigned short seskey;
	unsigned int counter;
	unsigned char *data;
};

void parsePacket(unsigned char *data, struct mt_mactelnet_hdr *pkthdr) {
	pkthdr->ver = data[0];
	pkthdr->ptype = data[1];
	memcpy(pkthdr->srcaddr, data+2,6);
	memcpy(pkthdr->dstaddr, data+8,6);
	pkthdr->seskey = data[16] << 8 | data[17];
	pkthdr->counter = data[18] << 24 | data[19] << 16 | data[20] << 8 | data[21];
	pkthdr->data = data + 22;
}

int sockfd;
int counter=0;
unsigned char *src = "00:e0:81:b5:ac:8e";
unsigned char *dst = "00:0c:42:43:58:a4";

void parseControlPacket(unsigned char *data, int data_len) {
	unsigned char magic[] = { 0x56, 0x34, 0x12, 0xff };
	if (memcmp(data,&magic,4) == 0) {
		if (DEBUG)
			printf("\tControl packet:\n\t\tType: %d\n\t\tLength: %d\n", data[4], data[5]<<24|data[6]<<16|data[7]<<8|data[8]);
		if (data_len - 9 - (data[4], data[5]<<24|data[6]<<16|data[7]<<8|data[8]) > 0) {
			parseControlPacket(data + 9 + (data[4], data[5]<<24|data[6]<<16|data[7]<<8|data[8]), data_len - 9 - (data[4], data[5]<<24|data[6]<<16|data[7]<<8|data[8]));
		}

		if (data[4] == 1) {
			printf("Connected. Enter username & password.\n\n"); // TODOD: Teh good shiat
		}
	}
}

void handlePacket(unsigned char *data, int data_len) {
	struct mt_mactelnet_hdr pkthdr;
	parsePacket(data, &pkthdr);

	if (DEBUG)
		printf("Received packet:\n\tVersion %d\n\tType: %d\n\tSesskey: %d\n\tCounter: %d\n\n", pkthdr.ver, pkthdr.ptype, pkthdr.seskey, pkthdr.counter);

	if (pkthdr.ptype == MT_PTYPE_DATA) {
		char odata[200];
		int plen=0,result=0;
		counter += data_len - 22;
		plen = initPacket(odata, MT_PTYPE_ACK, src, dst, pkthdr.seskey, counter);
		result = sendCustomUDP(sockfd, src, dst, "213.236.240.252", 20561, "255.255.255.255", 20561, odata, plen);
		if (DEBUG)
			printf("ACK: Plen = %d, Send result: %d\n", plen, result);

		if (data_len - 22 > 0) {
			parseControlPacket(data + 22, data_len - 22);
		}
	}
}

int main (int argc, char **argv) {
	int outsockfd;
	int result;
	char data[200];
	struct sockaddr_in si_me;
	char buff[1500];
	int plen = 0;
	int sessionkey=0;

	srand(time(NULL));

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	outsockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(20561);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(outsockfd, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to port 20561\n");
		return 1;
	}

	sessionkey = rand() % 65535;

	printf("Connecting to %s...\n", dst);

	plen = initPacket(data, MT_PTYPE_SESSIONSTART, src, dst, sessionkey, 0);
	result = sendCustomUDP(sockfd, src, dst, "213.236.240.252", 20561, "255.255.255.255", 20561, data, plen);
	if (DEBUG)
		printf("Plen = %d, Send result: %d\n", plen, result);
	if (DEBUG)
		printf("Sessionkey: %d\n", sessionkey);

	result = recvfrom(outsockfd, buff, 1400, 0, 0, 0);
	handlePacket(buff, result);

	// TODO: Should resubmit whenever a PTYPE_DATA packet is sent, and an ACK packet with correct datacounter is received
	// or time out the connection, in all other cases.
	plen = initPacket(data, MT_PTYPE_DATA, src, dst, sessionkey, 0);
	plen += addControlPacket(data + plen, MT_CPTYPE_BEGINAUTH, NULL, 0);

	result = sendCustomUDP(sockfd, src, dst, "213.236.240.252", 20561, "255.255.255.255", 20561, data, plen);
	if (DEBUG)
		printf("Plen = %d, Send result: %d\n", plen, result);

	result = recvfrom(outsockfd, buff, 1400, 0, 0, 0);
	handlePacket(buff, result);

	result = recvfrom(outsockfd, buff, 1400, 0, 0, 0);
	handlePacket(buff, result);

	close(sockfd);

	return 0;
}
