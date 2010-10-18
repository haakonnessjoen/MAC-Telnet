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

#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#ifdef __APPLE_CC__
#include <net/if_dl.h>
#else
#include <malloc.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#endif

#ifndef IFT_ETHER
#define IFT_ETHER 0x6 /* Ethernet CSMACD */
#endif

int getDeviceMAC(const int sockfd, const unsigned char *deviceName, unsigned char *mac) {
	struct ifaddrs *addrs;
	const struct ifaddrs *cursor;
#ifdef __APPLE_CC__
	const struct sockaddr_dl *dlAddr;
#else
	const struct sockaddr_ll *dlAddr;
#endif
	
	if (getifaddrs(&addrs) == 0) {
		cursor = addrs;
		while (cursor != NULL) {
#ifdef __APPLE_CC__
			dlAddr = (const struct sockaddr_dl *) cursor->ifa_addr;
			if ( (cursor->ifa_addr->sa_family == AF_LINK) && (dlAddr->sdl_type == IFT_ETHER) ) {
				if (strcmp(cursor->ifa_name, deviceName) == 0) {
					memcpy(mac, dlAddr->sdl_data + dlAddr->sdl_nlen, 6);
					return 1;
				}
			}
#else
			dlAddr = (const struct sockaddr_ll *) cursor->ifa_addr;
			if (cursor->ifa_addr->sa_family == PF_PACKET) {
				if (strcmp(cursor->ifa_name, deviceName) == 0) {
					memcpy(mac, dlAddr->sll_addr, 6);
					return 1;
				}
			}
#endif
			cursor = cursor->ifa_next;
		}
		freeifaddrs(addrs);
	}
	return -1;
}

#ifndef __APPLE_CC__
/* Functions using NETDEVICE api */

int getDeviceIndex(int sockfd, unsigned char *deviceName) {
	struct ifreq ifr;

	/* Find interface index from deviceName */
	strncpy(ifr.ifr_name, deviceName, 16);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) {
		return -1;
	}

	/* Return interface index */
	return ifr.ifr_ifindex;
}

int getDeviceIp(const int sockfd, const unsigned char *deviceName, struct sockaddr_in *ip) {
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
#endif
