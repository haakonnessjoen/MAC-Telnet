#ifndef _MACTELNET_H
#define _MACTELNET_H 1

// Packet type
#define MT_PTYPE_SESSIONSTART 0
#define MT_PTYPE_DATA 1
#define MT_PTYPE_ACK 2
#define MT_PTYPE_END 255

// Control packet type
#define MT_CPTYPE_BEGINAUTH 0
#define MT_CPTYPE_ENCRYPTIONKEY 1
#define MT_CPTYPE_PASSWORD 2
#define MT_CPTYPE_USERNAME 3
#define MT_CPTYPE_TERM_TYPE 4
#define MT_CPTYPE_TERM_WIDTH 5
#define MT_CPTYPE_TERM_HEIGHT 6
#define MT_CPTYPE_PACKET_ERROR 7
#define MT_CPTYPE_END_AUTH 9

struct mt_mactelnet_hdr {
	unsigned char ver;
	unsigned char ptype;
	unsigned char srcaddr[6];
	unsigned char dstaddr[6];
	unsigned short seskey;
	unsigned int counter;
	unsigned char *data;
};

#endif
