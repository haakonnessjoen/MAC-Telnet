#ifndef _UDP_H
#define _UDP_H 1
extern int sendCustomUDP(const int socket, const char *sourcemac, const char *destmac, const char *sourceip, const int sourceport, const char *destip, const int destport, const char *data, const int datalen);
extern void etherAddrton(unsigned char *dest, const unsigned char *mac);
#endif
