
all: mactelnet

clean: dist-clean

dist-clean:
	rm -f mactelnet

mactelnet: main.c udp.h udp.c mactelnet.c mactelnet.h
	gcc -g -o mactelnet main.c udp.c mactelnet.c
