
all: mactelnet

clean: dist-clean

dist-clean:
	rm -f mactelnet

mactelnet: config.h main.c udp.h udp.c mactelnet.c mactelnet.h console.c console.h
	gcc -g -o mactelnet -lcrypto main.c udp.c mactelnet.c console.c devices.c
