
all: mactelnet mndp

clean: dist-clean

dist-clean:
	rm -f mactelnet mndp

install: all
	cp mndp $(DESTDIR)/usr/bin/
	cp mactelnet $(DESTDIR)/usr/sbin/

mactelnet: config.h main.c udp.h udp.c mactelnet.c mactelnet.h console.c console.h devices.c devices.h
	gcc -g -o mactelnet -lcrypto main.c udp.c mactelnet.c console.c devices.c

mndp: config.h mndp.c
	gcc -g -o mndp mndp.c
