#include <malloc.h>
#include <string.h>
#include <math.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <stdio.h>

//#define ETH_FRAME_LEN 1518
unsigned short in_cksum(unsigned short *addr, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short *w = addr;
	unsigned short answer = 0;
	
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	
	if (nleft == 1) {
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;
	return (answer);
}

unsigned char hex(const unsigned char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

unsigned char hex2(const unsigned char *p) {
    int i;
    unsigned char c;
    i = hex(*p++);
    if (i < 0) return i;
    c = (i << 4);
    i = hex(*p);
    if (i < 0) return i;
    return c | i;
}

void etherAddrton(unsigned char *dest, const unsigned char *mac) {
	const unsigned char *p = mac;
	int i = 0;

	do {
		if (*p == ':') {
			continue;
		}
		dest[i++] = hex2(p++);
	} while (*p++ && *p);
}

int sendCustomUDP(const int socket, const char *sourcemac, const char *destmac, const char *sourceip, const int sourceport, const char *destip, const int destport, const char *data, const int datalen) {
	struct sockaddr_ll socket_address;
	struct in_addr srcipaddr;
	struct in_addr dstipaddr;
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
	struct ethhdr *eh = (struct ethhdr *)buffer;
	struct iphdr *ip = (struct iphdr *)(buffer+14);
	struct udphdr *udp = (struct udphdr *)(buffer+14+20);
	unsigned char *resten = (unsigned char *)(buffer+20+14+sizeof(struct udphdr));
	static unsigned int id = 1;
	int send_result = 0;

	// Ethernet header
	etherAddrton(eh->h_source, sourcemac);
	etherAddrton(eh->h_dest, destmac);
	eh->h_proto = 8;

	// SendTo struct
	socket_address.sll_family   = PF_PACKET;	
	socket_address.sll_protocol = htons(ETH_P_IP);	
	socket_address.sll_ifindex  = 2;
	socket_address.sll_hatype   = ARPHRD_ETHER;
	socket_address.sll_pkttype  = PACKET_OTHERHOST;
	socket_address.sll_halen    = ETH_ALEN;		

	memcpy(socket_address.sll_addr, eh->h_source, 6);
	socket_address.sll_addr[6]  = 0x00;/*not used*/
	socket_address.sll_addr[7]  = 0x00;/*not used*/

	// TODO: errorhandling
	inet_aton(sourceip, &srcipaddr);
	inet_aton(destip, &dstipaddr);

	// IP Header
	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0x10;
	ip->tot_len = htons(datalen+8+20);
	ip->id = htons(id++);
	ip->frag_off = 0x0040;
	ip->ttl = 64;
	ip->protocol = 17; // UDP
	ip->check = 0x0000;
	ip->saddr = srcipaddr.s_addr;
	ip->daddr = dstipaddr.s_addr;
	ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

	// UDP Header
	udp->source = htons(20561);
	udp->dest = htons(20561);
	udp->len = htons(sizeof(struct udphdr) + datalen);

	memcpy(resten, data, datalen);

	/*send the packet*/
	send_result = sendto(socket, buffer, datalen+8+14+20, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	free(buffer);

	return send_result-8-14-20;
}
