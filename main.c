/* Sample UDP client */

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

int main(int argc, char**argv)
{
   int sockfd,n,r;
        int tolen;
   char msg[123];
   struct sockaddr myaddr, toaddr;
   char minaddr[] = {0x08, 0x00, 0x27, 0xd9, 0x92, 0xd3};
   char dinaddr[] = {0x08, 0x00, 0x27, 0xd9, 0x92, 0xd3};
   char sendline[1000];
   char recvline[1000];

   //sockfd=socket(AF_INET,SOCK_PACKET, htons(ETH_P_ALL));
   sockfd=socket(AF_INET,SOCK_RAW, htons(IPPROTO_RAW));

   bzero(&myaddr, sizeof(myaddr));
   myaddr.sa_family = AF_INET;
   memcpy(myaddr.sa_data, &minaddr, 6);
   //r = bind(sockfd, &myaddr, sizeof(struct sockaddr));

   bzero(&toaddr, sizeof(toaddr));
   toaddr.sa_family = AF_INET;
   memcpy(toaddr.sa_data, &dinaddr, 6);
        tolen = sizeof(toaddr);
  r = sendto(sockfd, &msg, 100, 0, &toaddr, tolen);
printf("Result: %d\n", r);
return 0;
}

