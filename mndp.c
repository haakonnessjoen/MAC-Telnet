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
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include "config.h"

int main(int argc, char **argv)  {
	int sock,result;
	struct sockaddr_in si_me;
	unsigned char buff[1500];
	unsigned short nameLen = 0;
	unsigned char name[100];
	unsigned char mac[ETH_ALEN];

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(5678);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(sock, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to %s:5678\n", inet_ntoa(si_me.sin_addr));
		return 1;
	}

	/* Write informative message to STDERR to make it easier to use the output in simple scripts */
	fprintf(stderr, "Searching for MikroTik routers... Abort with CTRL+C.\n");

	while(1) {
		result = recvfrom(sock, buff, 1500, 0, 0, 0);
		if (result < 0) {
			fprintf(stderr, "Error occured. aborting\n");
			exit(1);
		}

		memcpy(&nameLen, buff+16,2);
		nameLen = (nameLen >> 8) | ((nameLen&0xff)<<8);

		/* Max name length = 99 */
		nameLen = nameLen < 100 ? nameLen : 99;

		memcpy(&name, buff+18, nameLen);
		name[nameLen] = 0;

		memcpy(&mac, buff+8, ETH_ALEN);

		printf("%17s %s\n", ether_ntoa((struct ether_addr *)mac), name);
	}

	return 0;
}
