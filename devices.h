extern int get_device_index(int sockfd, char *deviceName);
extern int get_device_mac(const int sockfd, const char *deviceName, unsigned char *mac);
extern int get_device_ip(const int sockfd, const char *deviceName, struct sockaddr_in *ip);
int get_ips(char *name, int nameLen, struct sockaddr_in *ip);
