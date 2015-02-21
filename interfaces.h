/*
    Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
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
#ifndef _INTERFACES_H
#define _INTERFACES_H 1

#include <stdint.h>

#define ETH_FRAME_LEN   1514
#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
#define ETH_ALEN        6               /* Octets in one ethernet addr   */
#define IPV4_ALEN 4

struct iphdr {
  /* xxx: assumes little-endian */
  uint8_t   ihl:4,
            version:4;
  uint8_t   tos;
  uint16_t  tot_len;
  uint16_t  id;
  uint16_t  frag_off;
  uint8_t   ttl;
  uint8_t   protocol;
  uint16_t  check;
  uint32_t  saddr;
  uint32_t  daddr;
};

struct udphdr {
  uint16_t  source;
  uint16_t  dest;
  uint16_t  len;
  uint16_t check;
};


struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	unsigned short	h_proto;
} __attribute__((packed));

#define MAX_INTERFACES 32

struct net_interface {
	char name[256];
	unsigned char ipv4_addr[IPV4_ALEN];
	unsigned char mac_addr[ETH_ALEN];

	/* used by mactelnetd */
	int socketfd;

#ifdef __linux__
	int ifindex;
#endif
	int has_mac;
	int in_use;
};


extern int net_get_interfaces(struct net_interface *interfaces, int max_devices);
extern struct net_interface *net_get_interface_ptr(struct net_interface *interfaces, int max_devices, char *name, int create);
extern int net_init_raw_socket();
extern int net_send_udp(const int socket, struct net_interface *interface, const unsigned char *sourcemac, const unsigned char *destmac, const struct in_addr *sourceip, const int sourceport, const struct in_addr *destip, const int destport, const unsigned char *data, const int datalen);
extern unsigned short in_cksum(unsigned short *addr, int len);
#endif
