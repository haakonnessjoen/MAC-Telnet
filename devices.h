extern int getDeviceIndex(int sockfd, unsigned char *deviceName);
extern int getDeviceMAC(const int sockfd, const unsigned char *deviceName, unsigned char *mac);
extern int getDeviceIp(const int sockfd, const unsigned char *deviceName, struct sockaddr_in *ip);
int getIps(char *name, int nameLen, struct sockaddr_in *ip);
