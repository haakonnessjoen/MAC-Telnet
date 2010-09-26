#include <string.h>
#include <stdio.h>
#include "mactelnet.h"
#include "config.h"

int initPacket(unsigned char *data, unsigned char ptype, unsigned char *src, unsigned char *dst, unsigned short sessionkey, unsigned short counter) {

	// PACKET VERSION
	data[0] = 1;

	// PACKET TYPE
	data[1] = ptype;

	// src ethernet address
	etherAddrton(data + 2, src);

	// dst ethernet address
	etherAddrton(data + 8, dst);

	data[14] = sessionkey >> 8;
	data[15] = sessionkey & 0xff;

	data[16] = 0x00;
	data[17] = 0x15;

	data[18] = (counter >> 24) & 0xff;
	data[19] = (counter >> 16) & 0xff;
	data[20] = (counter >> 8) & 0xff;
	data[21] = counter & 0xff;

	return 22;
}

int addControlPacket(unsigned char *data, unsigned char cptype, unsigned char *cpdata, int data_len) {
	data[0] = 0x56;
	data[1] = 0x34;
	data[2] = 0x12;
	data[3] = 0xff;

	// Control packet type
	data[4] = cptype;

	// Data length
	data[5] = (data_len >> 24) & 0xff;
	data[6] = (data_len >> 16) & 0xff;
	data[7] = (data_len >> 8) & 0xff;
	data[8] = data_len & 0xff;

	if (data_len) {
		memcpy(data+9, cpdata, data_len);
	}

	return 9+data_len;
}

void parsePacket(unsigned char *data, struct mt_mactelnet_hdr *pkthdr) {
	pkthdr->ver = data[0];
	pkthdr->ptype = data[1];
	memcpy(pkthdr->srcaddr, data+2,6);
	memcpy(pkthdr->dstaddr, data+8,6);
	pkthdr->seskey = data[16] << 8 | data[17];
	pkthdr->counter = data[18] << 24 | data[19] << 16 | data[20] << 8 | data[21];
	pkthdr->data = data + 22;
}


int parseControlPacket(unsigned char *data, const int data_len, struct mt_mactelnet_control_hdr *cpkthdr) {
	unsigned char magic[] = { 0x56, 0x34, 0x12, 0xff };

	if (data_len <= 0)
		return 0;

	if (memcmp(data, &magic, 4) == 0) {
		if (DEBUG)
			printf("\t----Control packet:\n\t\tType: %d\n\t\tLength: %d\n", data[4], data[5]<<24|data[6]<<16|data[7]<<8|data[8]);

		cpkthdr->cptype = data[4];
		cpkthdr->length = data[5]<<24|data[6]<<16|data[7]<<8|data[8];
		cpkthdr->data = data + 9;

		return cpkthdr->length + 9;

	} else {
		cpkthdr->cptype = MT_CPTYPE_PLAINDATA;
		cpkthdr->length = data_len;
		cpkthdr->data = data;
		return data_len;
	}
}

