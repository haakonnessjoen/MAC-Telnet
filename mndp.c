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
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <string.h>
#include "protocol.h"
#include "config.h"

int main(int argc, char **argv)  {
	int sock,result;
	int optval = 1;
	struct sockaddr_in si_me, si_remote;
	unsigned char buff[MT_PACKET_LEN];
	unsigned short nameLen = 0;
	unsigned char name[MT_MNDP_MAX_NAME_LENGTH + 1];
	unsigned char mac[ETH_ALEN];

	/* Open a UDP socket handle */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	/* Set initialize address/port */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(MT_MNDP_PORT);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	/* Bind to specified address/port */
	if (bind(sock, (struct sockaddr *)&si_me, sizeof(si_me))==-1) {
		fprintf(stderr, "Error binding to %s:%d\n", inet_ntoa(si_me.sin_addr), MT_MNDP_PORT);
		return 1;
	}

	/* Write informative message to STDERR to make it easier to use the output in simple scripts */
	fprintf(stderr, "Searching for MikroTik routers... Abort with CTRL+C.\n");

	/* Set the socket to allow sending broadcast packets */
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval))==-1) {
		fprintf(stderr, "Unable to send broadcast packets: Operating in receive only mode.\n");
	} else {
		/* Request routers identify themselves */
		unsigned int message = 0;

		memset((char *) &si_remote, 0, sizeof(si_remote));
		si_remote.sin_family = AF_INET;
		si_remote.sin_port = htons(MT_MNDP_PORT);
		si_remote.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		if (sendto (sock, &message, sizeof (message), 0, (struct sockaddr *)&si_remote, sizeof(si_remote))==-1) {
			fprintf(stderr, "Unable to send broadcast packet: Operating in receive only mode.\n");
		}
	}

	while(1) {
		/* Wait for a UDP packet */
		result = recvfrom(sock, buff, MT_PACKET_LEN, 0, 0, 0);
		if (result < 0) {
			fprintf(stderr, "Error occured. aborting\n");
			exit(1);
		}

		/* Check for valid packet length */
		if (result < 18) {
			continue;
		}

		/* Fetch length of Identifier string */
		memcpy(&nameLen, buff+16,2);
		nameLen = (nameLen >> 8) | ((nameLen&0xff)<<8);

		/* Enforce maximum name length */
		nameLen = nameLen < sizeof(name) ? nameLen : MT_MNDP_MAX_NAME_LENGTH;

		/* Read Identifier string */
		memcpy(&name, buff+18, nameLen);

		/* Append zero */
		name[nameLen] = 0;

		/* Read source MAC address */
		memcpy(&mac, buff+8, ETH_ALEN);

		/* Print it */
		printf("%17s %s\n", ether_ntoa((struct ether_addr *)mac), name);
	}

	/* We'll never get here.. */
	return 0;
}
