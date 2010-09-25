#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include "udp.h"

int main (int argc, char **argv) {
	int sockfd;
	int result;
	char data[11] = "1234567890";

	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	result = sendCustomUDP(sockfd, "00:19:db:66:e5::bf", "04:1e:64:ea:e5:15", "10.0.0.100", 20561, "255.255.255.255", 20561, data, 10);
	printf("Send result: %d\n", result);
	close(sockfd);

	return 0;
}
