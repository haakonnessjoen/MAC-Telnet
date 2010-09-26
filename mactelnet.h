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
// Internal CPTYPE, not part of protocol
#define MT_CPTYPE_PLAINDATA -1

struct mt_mactelnet_hdr {
	unsigned char ver;
	unsigned char ptype;
	unsigned char srcaddr[6];
	unsigned char dstaddr[6];
	unsigned short seskey;
	unsigned int counter;
	unsigned char *data;
};

struct mt_mactelnet_control_hdr {
	signed char cptype;
	unsigned int length;
	unsigned char *data;
};

#endif
