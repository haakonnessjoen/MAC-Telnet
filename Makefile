
all: mactelnet

mactelnet: main.c udp.h udp.c
	gcc -o mactelnet main.c udp.c
