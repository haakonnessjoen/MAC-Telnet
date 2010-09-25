#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include "udp.h"

struct mactelnet_cli_hdr {
	unsigned char ver;
	unsigned char packet_type;
	unsigned char srcaddr[6];
	unsigned char dstaddr[6];
	unsigned short sessionkey;
	unsigned short magic;
	unsigned int counter;
};

#define MT_PTYPE_SESSIONSTART 0
#define MT_PTYPE_DATA 1
#define MT_PTYPE_ACK 2
#define MT_PTYPE_END 255

int main (int argc, char **argv) {
	int sockfd;
	int outsockfd;
	int result;
	char data[200];
	struct sockaddr_in si_me;
	char buff[1500];
	struct mactelnet_cli_hdr outpacket;

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	outsockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(20561);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(outsockfd, &si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to port 20561\n");
		return 1;
	}

	outpacket.ver = 1;
	outpacket.packet_type = MT_PTYPE_SESSIONSTART;
	etherAddrton(outpacket.srcaddr, "00:e0:81:b5:ac:8e");
	etherAddrton(outpacket.dstaddr, "00:0c:42:43:58:a4");
	outpacket.sessionkey = 1234;
	outpacket.magic = 0x1500;
	outpacket.counter = 0;
/*
	data[0] = 1;
	data[1] = 0;

	etherAddrton(&data[2], "00:e0:81:b5:ac:8e");
	etherAddrton(&data[8], "00:0c:42:43:58:a4");

	data[14] = 22;
	data[15] = 12;
	data[16] = 0;
	data[17] = 0x15;

	data[18] = 0;
	data[19] = 0;

	data[20] = 0;
	data[21] = 0;
	data[22] = 0;

	data[23] = 0;
*/	
	result = sendCustomUDP(sockfd, "00:e0:81:b5:ac:8e", "00:0c:42:43:58:a4", "213.236.240.252", 20561, "255.255.255.255", 20561, (unsigned char *)&outpacket, sizeof(outpacket));
	printf("Send result: %d\n", result);

	result = recvfrom(outsockfd, buff, 1400, 0, 0, 0);
	printf("receive result: %d\n", result);


	data[0] = 1;
	data[1] = 1;

	etherAddrton(&data[2], "00:e0:81:b5:ac:8e");
	etherAddrton(&data[8], "00:0c:42:43:58:a4");

	data[14] = 22;
	data[15] = 12;
	data[16] = 0;
	data[17] = 0x15;

	data[18] = 0;
	data[19] = 0;
	data[20] = 0;
	data[21] = 1;

	data[22] = 0x56;
	data[23] = 0x34;
	data[24] = 0x12;
	data[25] = 0xff;

	// type
	data[26] = 0;

	//len
	data[27] = 0;
	data[28] = 0;
	data[29] = 0;
	data[30] = 0;
	
	result = sendCustomUDP(sockfd, "00:e0:81:b5:ac:8e", "00:0c:42:43:58:a4", "213.236.240.252", 20561, "255.255.255.255", 20561, data, 31);
	printf("Send result: %d\n", result);

	result = recvfrom(outsockfd, buff, 1400, 0, 0, 0);
	printf("receive result: %d\n", result);


	close(sockfd);

	return 0;
}
