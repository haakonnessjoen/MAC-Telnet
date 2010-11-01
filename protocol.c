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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include "protocol.h"
#include "config.h"

unsigned char mt_mactelnet_cpmagic[4] = { 0x56, 0x34, 0x12, 0xff };
unsigned char mt_mactelnet_clienttype[2] = { 0x00, 0x15 };


int initPacket(struct mt_packet *packet, unsigned char ptype, unsigned char *srcmac, unsigned char *dstmac, unsigned short sessionkey, unsigned int counter) {
	unsigned char *data = packet->data;

	/* Packet version */
	data[0] = 1;

	/* Packet type */
	data[1] = ptype;

	/* src ethernet address */
	memcpy(data + 2, srcmac, ETH_ALEN);

	/* dst ethernet address */
	memcpy(data + 8, dstmac, ETH_ALEN);

	if (mt_direction_fromserver) {
		/* Session key */
		data[16] = sessionkey >> 8;
		data[17] = sessionkey & 0xff;

		/* Client type: Mac Telnet */
		memcpy(data + 14, &mt_mactelnet_clienttype, sizeof(mt_mactelnet_clienttype));
	} else {
		/* Session key */
		data[14] = sessionkey >> 8;
		data[15] = sessionkey & 0xff;

		/* Client type: Mac Telnet */
		memcpy(data + 16, &mt_mactelnet_clienttype, sizeof(mt_mactelnet_clienttype));
	}

	/* Received/sent data counter */
	data[18] = (counter >> 24) & 0xff;
	data[19] = (counter >> 16) & 0xff;
	data[20] = (counter >> 8) & 0xff;
	data[21] = counter & 0xff;

	/* 22 bytes header */
	packet->size = 22;
	return 22;
}

int addControlPacket(struct mt_packet *packet, char cptype, void *cpdata, int data_len) {
	unsigned char *data = packet->data + packet->size;

	/* Something is really wrong. Packets should never become over 1500 bytes */
	if (packet->size + MT_CPHEADER_LEN + data_len > MT_PACKET_LEN) {
		fprintf(stderr, "addControlPacket: ERROR, too large packet. Exceeds %d bytes\n", MT_PACKET_LEN);
		return -1;
		//exit(1);
	}

	/* PLAINDATA isn't really a controlpacket, but we handle it here, since
	   parseControlPacket also parses raw data as PLAINDATA */
	if (cptype == MT_CPTYPE_PLAINDATA) {
		memcpy(data, cpdata, data_len);
		packet->size += data_len;
		return data_len;
	}

	/* Control Packet Magic id */
	memcpy(data,  mt_mactelnet_cpmagic, sizeof(mt_mactelnet_cpmagic));

	/* Control packet type */
	data[4] = cptype;

	/* Data length */
	data[5] = (data_len >> 24) & 0xff;
	data[6] = (data_len >> 16) & 0xff;
	data[7] = (data_len >> 8) & 0xff;
	data[8] = data_len & 0xff;

	/* Insert data */
	if (data_len) {
		memcpy(data + MT_CPHEADER_LEN, cpdata, data_len);
	}

	packet->size += MT_CPHEADER_LEN + data_len;
	/* Control packet header length + data length */
	return MT_CPHEADER_LEN + data_len;
}

void parsePacket(unsigned char *data, struct mt_mactelnet_hdr *pkthdr) {
	/* Packet version */
	pkthdr->ver = data[0];

	/* Packet type */
	pkthdr->ptype = data[1];

	/* src ethernet addr */
	memcpy(pkthdr->srcaddr, data+2,6);

	/* dst ethernet addr */
	memcpy(pkthdr->dstaddr, data+8,6);

	if (mt_direction_fromserver) {
		/* Session key */
		pkthdr->seskey = data[14] << 8 | data[15];

		/* server type */
		memcpy(&(pkthdr->clienttype), data+16, 2);
	} else {
		/* server type */
		memcpy(&(pkthdr->clienttype), data+14, 2);

		/* Session key */
		pkthdr->seskey = data[16] << 8 | data[17];
	}

	/* Received/sent data counter */
	pkthdr->counter = data[18] << 24 | data[19] << 16 | data[20] << 8 | data[21];

	/* Set pointer to actual data */
	pkthdr->data = data + 22;
}


int parseControlPacket(unsigned char *data, const int data_len, struct mt_mactelnet_control_hdr *cpkthdr) {

	if (data_len < 0)
		return 0;

	/* Check for valid minimum packet length & magic header */
	if (data_len >= 9 && memcmp(data, &mt_mactelnet_cpmagic, 4) == 0) {

		/* Control packet type */
		cpkthdr->cptype = data[4];

		/* Control packet data length */
		cpkthdr->length = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

		/* Set pointer to actual data */
		cpkthdr->data = data + 9;

		/* Return number of bytes in packet */
		return cpkthdr->length + 9;

	} else {
		/* Mark data as raw terminal data */
		cpkthdr->cptype = MT_CPTYPE_PLAINDATA;
		cpkthdr->length = data_len;
		cpkthdr->data = data;

		/* Consume the whole rest of the packet */
		return data_len;
	}
}

struct mt_mndp_packet *parseMNDP(const char *data, const int packetLen) {
	static struct mt_mndp_packet packet;
	unsigned short nameLen = 0;

	/* Check for valid packet length */
	if (packetLen < 18) {
		return NULL;
	}

	/* Fetch length of Identifier string */
	memcpy(&nameLen, data + 16,2);
	nameLen = (nameLen >> 8) | ((nameLen & 0xff) << 8);

	/* Enforce maximum name length */
	nameLen = nameLen < MT_MNDP_MAX_IDENTITY_LENGTH ? nameLen : MT_MNDP_MAX_IDENTITY_LENGTH;

	/* Read Identifier string */
	memcpy(packet.identity, data + 18, nameLen);

	/* Append zero */
	packet.identity[nameLen] = 0;

	/* Read source MAC address */
	memcpy(packet.address, data + 8, ETH_ALEN);

	return &packet;
}

int queryMNDP(const unsigned char *identity, unsigned char *mac) {
	int fastlookup = 0;
	int sock, length;
	int optval = 1;
	struct sockaddr_in si_me, si_remote;
	unsigned char buff[MT_PACKET_LEN];
	unsigned int message = 0;
	struct timeval timeout;
	time_t startTime;
	fd_set read_fds;
	struct mt_mndp_packet *packet;

	startTime = time(0);

	/* Open a UDP socket handle */
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	/* Set initialize address/port */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(MT_MNDP_PORT);
	si_me.sin_addr.s_addr = htonl(INADDR_ANY);

	/* Bind to specified address/port */
	if (bind(sock, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
		fprintf(stderr, "Error binding to %s:%d\n", inet_ntoa(si_me.sin_addr), MT_MNDP_PORT);
		return 0;
	}

	/* Set the socket to allow sending broadcast packets */
	setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval));

	/* Request routers identify themselves */
	memset((char *) &si_remote, 0, sizeof(si_remote));
	si_remote.sin_family = AF_INET;
	si_remote.sin_port = htons(MT_MNDP_PORT);
	si_remote.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	if (sendto(sock, &message, sizeof (message), 0, (struct sockaddr *)&si_remote, sizeof(si_remote)) == -1) {
		fprintf(stderr, "Unable to send broadcast packet: Router lookup will be slow\n");
		fastlookup = 0;
	} else {
		fastlookup = 1;
	}

	while (1) {
		/* Timeout, in case we receive a lot of packets, but from the wrong routers */
		if (time(0) - startTime > (fastlookup ? MT_MNDP_TIMEOUT : MT_MNDP_LONGTIMEOUT)) {
			return 0;
		}

		FD_ZERO(&read_fds);
		FD_SET(sock, &read_fds);

		timeout.tv_sec = fastlookup ? MT_MNDP_TIMEOUT : MT_MNDP_LONGTIMEOUT;
		timeout.tv_usec = 0;
	
		select(sock + 1, &read_fds, NULL, NULL, &timeout);
		if (!FD_ISSET(sock, &read_fds)) {
			return 0;
		}

		/* Read UDP packet */
		length = recvfrom(sock, buff, MT_PACKET_LEN, 0, 0, 0);
		if (length < 0) {
			return 0;
		}

		/* Parse MNDP packet */
		packet = parseMNDP(buff, length);

		if (packet != NULL) {
			if (strcasecmp(identity, packet->identity) == 0) {
				memcpy(mac, packet->address, ETH_ALEN);
				return 1;
			}
		}
	}
}
