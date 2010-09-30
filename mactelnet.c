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
#include <linux/if_ether.h>
#include "mactelnet.h"
#include "config.h"

unsigned char mt_mactelnet_cpmagic[4] = { 0x56, 0x34, 0x12, 0xff };

int initPacket(unsigned char *data, unsigned char ptype, unsigned char *srcmac, unsigned char *dstmac, unsigned short sessionkey, unsigned short counter) {

	/* Packet version */
	data[0] = 1;

	/* Packet type */
	data[1] = ptype;

	/* src ethernet address */
	memcpy(data + 2, srcmac, ETH_ALEN);

	/* dst ethernet address */
	memcpy(data + 8, dstmac, ETH_ALEN);

	/* Session key */
	data[14] = sessionkey >> 8;
	data[15] = sessionkey & 0xff;

	/* Magic number */
	data[16] = 0x00;
	data[17] = 0x15;

	/* Received/sent data counter */
	data[18] = (counter >> 24) & 0xff;
	data[19] = (counter >> 16) & 0xff;
	data[20] = (counter >> 8) & 0xff;
	data[21] = counter & 0xff;

	/* 22 bytes header */
	return 22;
}

int addControlPacket(unsigned char *data, unsigned char cptype, void *cpdata, int data_len) {
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
		memcpy(data+9, cpdata, data_len);
	}

	/* Control packet header length + data length */
	return 9+data_len;
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

	/* Session key */
	pkthdr->seskey = data[16] << 8 | data[17];

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
		if (DEBUG)
			printf("\t----Control packet:\n\t\tType: %d\n\t\tLength: %d\n", data[4], data[5]<<24|data[6]<<16|data[7]<<8|data[8]);

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

