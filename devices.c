#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>

int getDeviceIndex(int sockfd, unsigned char *deviceName) {
	struct ifreq ifr;

	strncpy(ifr.ifr_name, deviceName, 16);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) {
		return -1;
	}

	return ifr.ifr_ifindex;
}

int getDeviceIp(const int sockfd, const unsigned char *deviceName, struct sockaddr_in *ip) {
	struct ifconf ifc;
	struct ifreq *ifr;
	int i,numDevices;

	memset(&ifc, 0, sizeof(ifc));
	if (ioctl(sockfd, SIOCGIFCONF, &ifc) != 0) {
		return -1;
	}

	if ((ifr = malloc(ifc.ifc_len * 2)) == NULL) {
		perror("malloc");
		exit(1);
	}

	ifc.ifc_req = ifr;

	if (ioctl(sockfd, SIOCGIFCONF, &ifc) != 0) {
		free(ifr);
                return -1;
        }

	numDevices = ifc.ifc_len / sizeof(struct ifreq);
	for (i = 0; i < numDevices; ++i) {
		if (strcmp(ifr[i].ifr_name, deviceName) == 0) {
			memcpy(ip, &(ifr[i].ifr_addr), sizeof(ip));
			free(ifr);
			return 1;
		}
	}
	free(ifr);
	return -1;
}
