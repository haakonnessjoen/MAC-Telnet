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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <malloc.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/in.h>


/* Functions using NETDEVICE api */

int getDeviceIndex(int sockfd, char *deviceName) {
	struct ifreq ifr;

	/* Find interface index from deviceName */
	strncpy(ifr.ifr_name, deviceName, 16);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) {
		return -1;
	}

	/* Return interface index */
	return ifr.ifr_ifindex;
}

int getDeviceMAC(const int sockfd, const char *deviceName, unsigned char *mac) {
	struct ifreq ifr;

	/* Find interface hardware address from deviceName */
	strncpy(ifr.ifr_name, deviceName, 16);
	if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) != 0) {
		return -1;
	}

	/* Fetch mac address */
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 1;
}

int getDeviceIp(const int sockfd, const char *deviceName, struct sockaddr_in *ip) {
	struct ifconf ifc;
	struct ifreq *ifr;
	int i,numDevices;

	/*
	 * Do a initial query without allocating ifreq structs
	 * to count the number of ifreq structs to allocate memory for
	*/
	memset(&ifc, 0, sizeof(ifc));
	if (ioctl(sockfd, SIOCGIFCONF, &ifc) != 0) {
		return -1;
	}

	/*
	 * Allocate memory for interfaces, multiply by two in case
	 * the number of interfaces has increased since last ioctl
	*/
	if ((ifr = malloc(ifc.ifc_len * 2)) == NULL) {
		perror("malloc");
		exit(1);
	}

	/* Do the actual query for info about all interfaces */
	ifc.ifc_req = ifr;
	if (ioctl(sockfd, SIOCGIFCONF, &ifc) != 0) {
		free(ifr);
		return -1;
	}

	/* Iterate through all devices, searching for interface */
	numDevices = ifc.ifc_len / sizeof(struct ifreq);
	for (i = 0; i < numDevices; ++i) {
		if (strcmp(ifr[i].ifr_name, deviceName) == 0) {
			/* Fetch IP for found interface */
			memcpy(ip, &(ifr[i].ifr_addr), sizeof(ip));
			free(ifr);
			return 1;
		}
	}
	free(ifr);
	return -1;
}

int getIps(char *name, int nameLen, struct sockaddr_in *ip) {
	static int first = 1;
	static struct ifaddrs *int_addrs;
	static const struct ifaddrs *int_cursor;
	const struct sockaddr_in *dlAddr;

	if (first == 1) {
		first = 0;
		if (getifaddrs(&int_addrs) == 0) {
			int_cursor = int_addrs;
		} else {
			first = 1;
			return 0;
		}
	}
	if (int_cursor != NULL) {
		while (int_cursor != NULL) {
			dlAddr = (const struct sockaddr_in *) int_cursor->ifa_addr;
			if (dlAddr != NULL && dlAddr->sin_family == AF_INET) {
				memcpy(ip, dlAddr, sizeof(struct sockaddr_in));
				strncpy(name, int_cursor->ifa_name, nameLen - 1);
				name[nameLen - 1] = '\0';
				int_cursor = int_cursor->ifa_next;
				return 1;
			}
			int_cursor = int_cursor->ifa_next;
		}
	}
	if (int_addrs != NULL) {
		freeifaddrs(int_addrs);
		int_addrs = NULL;
	}
	return 0;

}
