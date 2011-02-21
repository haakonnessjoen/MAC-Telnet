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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/if_ether.h>
#include "md5.h"
#include "protocol.h"
#include "udp.h"
#include "console.h"
#include "devices.h"
#include "config.h"
#include "mactelnet.h"

#define PROGRAM_NAME "MAC-Telnet"
#define PROGRAM_VERSION "0.2"

static int sockfd;
static int insockfd;
static int device_index;
static unsigned int outcounter = 0;
static unsigned int incounter = 0;
static int sessionkey = 0;
static int running = 1;

static unsigned char use_raw_socket = 0;
static unsigned char terminal_mode = 0;

static unsigned char srcmac[ETH_ALEN];
static unsigned char dstmac[ETH_ALEN];

static struct in_addr sourceip; 
static struct in_addr destip;
static int sourceport;

static int connect_timeout = CONNECT_TIMEOUT;

static int keepalive_counter = 0;

static unsigned char encryptionkey[128];
static char username[255];
static char password[255];

/* Protocol data direction */
unsigned char mt_direction_fromserver = 0;

static unsigned int send_socket;

static void print_version() {
	fprintf(stderr, PROGRAM_NAME " " PROGRAM_VERSION "\n");
}

static int send_udp(struct mt_packet *packet, int retransmit) {
	int sent_bytes;

	/* Clear keepalive counter */
	keepalive_counter = 0;

	if (!use_raw_socket) {
		/* Init SendTo struct */
		struct sockaddr_in socket_address;
		socket_address.sin_family = AF_INET;
		socket_address.sin_port = htons(MT_MACTELNET_PORT);
		socket_address.sin_addr.s_addr = htonl(INADDR_BROADCAST);

		sent_bytes = sendto(send_socket, packet->data, packet->size, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
	} else {
		sent_bytes = send_custom_udp(sockfd, device_index, srcmac, dstmac, &sourceip,  sourceport, &destip, MT_MACTELNET_PORT, packet->data, packet->size);
	}

	/* 
	 * Retransmit packet if no data is received within
	 * retransmit_intervals milliseconds.
	 * 
	 * TODO: Only stop retransmitting if received packet is
	 * an ACK packet.
	 */
	if (retransmit) {
		int i;

		for (i = 0; i < MAX_RETRANSMIT_INTERVALS; ++i) {
			fd_set read_fds;
			int reads;
			struct timeval timeout;
			int interval = retransmit_intervals[i] * 1000;

			/* Init select */
			FD_ZERO(&read_fds);
			FD_SET(insockfd, &read_fds);
			timeout.tv_sec = 0;
			timeout.tv_usec = interval;

			/* Wait for data or timeout */
			reads = select(insockfd + 1, &read_fds, NULL, NULL, &timeout);
			if (reads && FD_ISSET(insockfd, &read_fds)) {
				return sent_bytes;
			}

			/* Retransmit */
			send_udp(packet, 0);
		}

		if (terminal_mode)
			reset_term();

		fprintf(stderr, "\nConnection timed out\n");
		exit(1);
	}
	return sent_bytes;
}

static void send_auth(char *username, char *password) {
	struct mt_packet data;
	unsigned short width = 0;
	unsigned short height = 0;
	char *terminal = getenv("TERM");
	char md5data[100];
	unsigned char md5sum[17];
	int result;
	int plen;
	md5_state_t state;

	/* Concat string of 0 + password + encryptionkey */
	md5data[0] = 0;
	strncpy(md5data + 1, password, 82);
	md5data[83] = '\0';
	memcpy(md5data + 1 + strlen(password), encryptionkey, 16);

	/* Generate md5 sum of md5data with a leading 0 */
	md5_init(&state);
	md5_append(&state, (const md5_byte_t *)md5data, strlen(password) + 17);
	md5_finish(&state, (md5_byte_t *)md5sum + 1);
	md5sum[0] = 0;

	/* Send combined packet to server */
	init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
	plen = add_control_packet(&data, MT_CPTYPE_PASSWORD, md5sum, 17);
	plen += add_control_packet(&data, MT_CPTYPE_USERNAME, username, strlen(username));
	plen += add_control_packet(&data, MT_CPTYPE_TERM_TYPE, terminal, strlen(terminal));
	
	if (get_terminal_size(&width, &height) != -1) {
#if BYTE_ORDER == BIG_ENDIAN
		/* Seems like Mikrotik are sending data little_endianed? */
		width = ((width & 0xff) << 8) | ((width & 0xff00) >> 8);
		height = ((height & 0xff) << 8) | ((height & 0xff00) >> 8);
#endif
		plen += add_control_packet(&data, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_HEIGHT, &height, 2);
	}

	outcounter += plen;

	/* TODO: handle result */
	result = send_udp(&data, 1);
}

static void sig_winch(int sig) {
	unsigned short width,height;
	struct mt_packet data;
	int result,plen;

	/* terminal height/width has changed, inform server */
	if (get_terminal_size(&width, &height) != -1) {
		init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
		plen = add_control_packet(&data, MT_CPTYPE_TERM_WIDTH, &width, 2);
		plen += add_control_packet(&data, MT_CPTYPE_TERM_HEIGHT, &height, 2);
		outcounter += plen;

		result = send_udp(&data, 1);
	}

	/* reinstate signal handler */
	signal(SIGWINCH, sig_winch);
}

static void handle_packet(unsigned char *data, int data_len) {
	struct mt_mactelnet_hdr pkthdr;
	parse_packet(data, &pkthdr);

	/* We only care about packets with correct sessionkey */
	if (pkthdr.seskey != sessionkey) {
		return;
	}

	/* Handle data packets */
	if (pkthdr.ptype == MT_PTYPE_DATA) {
		struct mt_packet odata;
		struct mt_mactelnet_control_hdr cpkt;
		int result=0;
		int success = 0;

		/* Always transmit ACKNOWLEDGE packets in response to DATA packets */
		init_packet(&odata, MT_PTYPE_ACK, srcmac, dstmac, sessionkey, pkthdr.counter + (data_len - MT_HEADER_LEN));
		result = send_udp(&odata, 0);

		/* Accept first packet, and all packets greater than incounter, and if counter has
		wrapped around. */
		if (incounter == 0 || pkthdr.counter > incounter || (incounter - pkthdr.counter) > 65535) {
			incounter = pkthdr.counter;
		} else {
			/* Ignore double or old packets */
			return;
		}

		/* Parse controlpacket data */
		success = parse_control_packet(data + MT_HEADER_LEN, data_len - MT_HEADER_LEN, &cpkt);

		while (success) {

			/* If we receive encryptionkey, transmit auth data back */
			if (cpkt.cptype == MT_CPTYPE_ENCRYPTIONKEY) {
				memcpy(encryptionkey, cpkt.data, cpkt.length);
				send_auth(username, password);
			}

			/* If the (remaining) data did not have a control-packet magic byte sequence,
			   the data is raw terminal data to be outputted to the terminal. */
			else if (cpkt.cptype == MT_CPTYPE_PLAINDATA) {
				cpkt.data[cpkt.length] = 0;
				printf("%s", cpkt.data);
			}

			/* END_AUTH means that the user/password negotiation is done, and after this point
			   terminal data may arrive, so we set up the terminal to raw mode. */
			else if (cpkt.cptype == MT_CPTYPE_END_AUTH) {
				/* stop input buffering at all levels. Give full control of terminal to RouterOS */
				raw_term();
				setvbuf(stdin,  (char*)NULL, _IONBF, 0);

				/* we have entered "terminal mode" */
				terminal_mode = 1;

				/* Add resize signal handler */
				signal(SIGWINCH, sig_winch);
			}

			/* Parse next controlpacket */
			success = parse_control_packet(NULL, 0, &cpkt);
		}
	}
	else if (pkthdr.ptype == MT_PTYPE_ACK) {
		/* TODO: If we were resubmitting lost messages, stop resubmitting here if received counter is correct. */
	}

	/* The server wants to terminate the connection, we have to oblige */
	else if (pkthdr.ptype == MT_PTYPE_END) {
		struct mt_packet odata;
		int result=0;

		/* Acknowledge the disconnection by sending a END packet in return */
		init_packet(&odata, MT_PTYPE_END, srcmac, dstmac, pkthdr.seskey, 0);
		result = send_udp(&odata, 0);

		fprintf(stderr, "Connection closed.\n");

		/* exit */
		running = 0;
	} else {
		fprintf(stderr, "Unhandeled packet type: %d received from server %s\n", pkthdr.ptype, ether_ntoa((struct ether_addr *)dstmac));
	}
}

static int find_interface() {
	struct mt_packet data;
	struct sockaddr_in myip;
	int success;
	char devicename[128];
	int testsocket;
	fd_set read_fds;
	struct timeval timeout;
	int optval = 1;
	
	while ((success = get_ips(devicename, 128, &myip))) {
		char str[INET_ADDRSTRLEN];

		/* Skip loopback interfaces */
		if (memcmp("lo", devicename, 2) == 0) {
			continue;
		}

		inet_ntop(AF_INET, &(myip.sin_addr), str, INET_ADDRSTRLEN);

		/* Initialize receiving socket on the device chosen */
		myip.sin_port = htons(sourceport);
	
		/* Initialize socket and bind to udp port */
		if ((testsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			continue;
		}

		setsockopt(testsocket, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
		setsockopt(testsocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

		if (bind(testsocket, (struct sockaddr *)&myip, sizeof(struct sockaddr_in)) == -1) {
			close(testsocket);
			continue;
		}

		/* Find the mac address for the current device */
		if (get_device_mac(testsocket, devicename, srcmac) < 0) {
			close(testsocket);
			continue;
		}

		/* Set the global socket handle for send_udp() */
		send_socket = testsocket;

		/* Send a SESSIONSTART message with the current device */
		init_packet(&data, MT_PTYPE_SESSIONSTART, srcmac, dstmac, sessionkey, 0);
		send_udp(&data, 0);

		timeout.tv_sec = connect_timeout;
		timeout.tv_usec = 0;

		FD_ZERO(&read_fds);
		FD_SET(insockfd, &read_fds);
		select(insockfd + 1, &read_fds, NULL, NULL, &timeout);
		if (FD_ISSET(insockfd, &read_fds)) {
			/* We got a response, this is the correct device to use */
			return 1;
		}

		close(testsocket);
	}

	/* We didn't find anything */
	return 0;
}

/*
 * TODO: Rewrite main() when all sub-functionality is tested
 */
int main (int argc, char **argv) {
	int result;
	struct mt_packet data;
	struct sockaddr_in si_me;
	unsigned char buff[1500];
	unsigned char print_help = 0, have_username = 0, have_password = 0;
	int c;
	int optval = 1;

	while (1) {
		c = getopt(argc, argv, "nt:u:p:vh?");

		if (c == -1)
			break;

		switch (c) {

			case 'n':
				use_raw_socket = 1;
				break;

			case 'u':
				/* Save username */
				strncpy(username, optarg, sizeof(username) - 1);
				username[sizeof(username) - 1] = '\0';
				have_username = 1;
				break;

			case 'p':
				/* Save password */
				strncpy(password, optarg, sizeof(password) - 1);
				password[sizeof(password) - 1] = '\0';
				have_password = 1;
				break;

			case 't':
				connect_timeout = atoi(optarg);
				break;

			case 'v':
				print_version();
				exit(0);
				break;

			case 'h':
			case '?':
				print_help = 1;
				break;

		}
	}
	if (argc - optind < 1 || print_help) {
		print_version();
		fprintf(stderr, "Usage: %s <MAC|identity> [-h] [-n] [-t <timeout>] [-u <username>] [-p <password>]\n", argv[0]);

		if (print_help) {
			fprintf(stderr, "\nParameters:\n");
			fprintf(stderr, "  ifname    Network interface that the RouterOS resides on. (example: eth0)\n");
			fprintf(stderr, "  MAC       MAC-Address of the RouterOS device. Use mndp to discover them.\n");
			fprintf(stderr, "  identity  The identity/name of your RouterOS device. Uses MNDP protocol to find it.\n");
			fprintf(stderr, "  -n        Do not use broadcast packets. Less insecure but requires root privileges.\n");
			fprintf(stderr, "  -t        Amount of seconds to wait for a response on each interface.\n");
			fprintf(stderr, "  -u        Specify username on command line.\n");
			fprintf(stderr, "  -p        Specify password on command line.\n");
			fprintf(stderr, "  -h        This help.\n");
			fprintf(stderr, "\n");
		}
		return 1;
	}

	/* Seed randomizer */
	srand(time(NULL));

	if (use_raw_socket) {
		if (geteuid() != 0) {
			fprintf(stderr, "You need to have root privileges to use the -n parameter.\n");
			return 1;
		}

		/* Transmit raw packets with this socket */
		sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (sockfd < 0) {
			perror("sockfd");
			return 1;
		}
	}

	/* Receive regular udp packets with this socket */
	insockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (insockfd < 0) {
		perror("insockfd");
		return 1;
	}

	if (!use_raw_socket) {
		if (setsockopt(insockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof (optval))==-1) {
			perror("SO_BROADCAST");
			return 1;
		}
	}

	/* Need to use, to be able to autodetect which interface to use */
	setsockopt(insockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval));

	/* Check for identity name or mac address */
	{
		char *p = argv[optind];
		int colons = 0;
		int dashs = 0;
		while (*p++) {
			if (*p == ':') {
				colons++;
			}
			else if (*p == '-') {
				dashs++;
			}
		}

		/* 
		 * Windows users often enter macs with dash instead
		 * of colon.
		 */
		if (colons == 0 && dashs == 5) {
			p = argv[optind];
			while (*p++) {
				if (*p == '-') {
					*p = ':';
				}
			}
			colons = dashs;
		}

		if (colons != 5) {
			fprintf(stderr, "Searching for '%s'...", argv[optind]);

			/* Search for Router by identity name, using MNDP */
			if (!query_mndp(argv[optind], dstmac)) {
				fprintf(stderr, "not found\n");
				return 1;
			}

			/* Router found, display mac and continue */
			fprintf(stderr, "found\n");

		} else {
			/* Convert mac address string to ether_addr struct */
			ether_aton_r(argv[optind], (struct ether_addr *)dstmac);
		}
	}

	if (!have_username) {
		printf("Login: ");
		scanf("%254s", username);
	}

	if (!have_password) {
		char *tmp;
		tmp = getpass("Passsword: ");
		strncpy(password, tmp, sizeof(password) - 1);
		password[sizeof(password) - 1] = '\0';
		/* security */
		memset(tmp, 0, strlen(tmp));
#ifdef __GNUC__
		free(tmp);
#endif
	}


	/* Set random source port */
	sourceport = 1024 + (rand() % 1024);

	/* Set up global info about the connection */
	inet_pton(AF_INET, (char *)"255.255.255.255", &destip);
	memcpy(&sourceip, &(si_me.sin_addr), 4);

	/* Sessioon key */
	sessionkey = rand() % 65535;

	/* stop output buffering */
	setvbuf(stdout, (char*)NULL, _IONBF, 0);

	printf("Connecting to %s...", ether_ntoa((struct ether_addr *)dstmac));

	/* Initialize receiving socket on the device chosen */
	memset((char *) &si_me, 0, sizeof(si_me));
	si_me.sin_family = AF_INET;
	si_me.sin_port = htons(sourceport);

	/* Bind to udp port */
	if (bind(insockfd, (struct sockaddr *)&si_me, sizeof(si_me)) == -1) {
		fprintf(stderr, "Error binding to %s:%d, %s\n", inet_ntoa(si_me.sin_addr), sourceport, strerror(errno));
		return 1;
	}

	if (!find_interface() || (result = recvfrom(insockfd, buff, 1400, 0, 0, 0)) < 1) {
		fprintf(stderr, "Connection failed.\n");
		return 1;
	}
	printf("done\n");

	/* Handle first received packet */
	handle_packet(buff, result);

	init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, 0);
	outcounter +=  add_control_packet(&data, MT_CPTYPE_BEGINAUTH, NULL, 0);

	/* TODO: handle result of send_udp */
	result = send_udp(&data, 1);

	while (running) {
		fd_set read_fds;
		int reads;
		struct timeval timeout;

		/* Init select */
		FD_ZERO(&read_fds);
		FD_SET(0, &read_fds);
		FD_SET(insockfd, &read_fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* Wait for data or timeout */
		reads = select(insockfd+1, &read_fds, NULL, NULL, &timeout);
		if (reads > 0) {
			/* Handle data from server */
			if (FD_ISSET(insockfd, &read_fds)) {
				memset(buff, 0, 1500);
				result = recvfrom(insockfd, buff, 1500, 0, 0, 0);
				handle_packet(buff, result);
			}
			/* Handle data from keyboard/local terminal */
			if (FD_ISSET(0, &read_fds)) {
				unsigned char keydata[512];
				int datalen;

				datalen = read(STDIN_FILENO, &keydata, 512);

				init_packet(&data, MT_PTYPE_DATA, srcmac, dstmac, sessionkey, outcounter);
				add_control_packet(&data, MT_CPTYPE_PLAINDATA, &keydata, datalen);
				outcounter += datalen;
				result = send_udp(&data, 1);
			}
		/* Handle select() timeout */
		} else {
			/* handle keepalive counter, transmit keepalive packet every 10 seconds
			   of inactivity  */
			if (keepalive_counter++ == 10) {
				struct mt_packet odata;
				int plen=0,result=0;
				plen = init_packet(&odata, MT_PTYPE_ACK, srcmac, dstmac, sessionkey, outcounter);
				result = send_udp(&odata, 0);
			}
		}
	}

	if (terminal_mode) {
		/* Reset terminal back to old settings */
		reset_term();
	}

	close(sockfd);
	close(insockfd);

	return 0;
}
