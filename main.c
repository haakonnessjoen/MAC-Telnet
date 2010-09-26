#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include "mactelnet.h"
#include "udp.h"
#include "config.h"

int sockfd;
int counter=0;
unsigned char *src = "00:e0:81:b5:ac:8e";
unsigned char *dst = "00:0c:42:43:58:a4";

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
