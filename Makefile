
all: mactelnet mactelnetd mndp

clean: dist-clean

dist-clean:
	rm -f mactelnet mactelnetd mndp

install: all
	cp mndp $(DESTDIR)/usr/bin/
	cp mactelnet $(DESTDIR)/usr/bin/
	cp mactelnetd $(DESTDIR)/usr/sbin/
	cp mactelnetd.users $(DESTDIR)/etc/
	chown $(DESTDIR)/etc/mactelnetd.users
	chmod 600 $(DESTDIR)/etc/mactelnetd.users

mactelnet: config.h udp.h udp.c mactelnet.c mactelnet.h protocol.c protocol.h console.c console.h devices.c devices.h md5.c md5.h
	gcc -Wall -g -DUSERSFILE='"/etc/mactelnetd.users"' -o mactelnet mactelnet.c udp.c protocol.c console.c devices.c md5.c

mactelnetd: config.h mactelnetd.c udp.h udp.c protocol.c protocol.h devices.c devices.h console.c console.h users.c users.h md5.c md5.h
	gcc -Wall -g -DUSERSFILE='"/etc/mactelnetd.users"' -o mactelnetd mactelnetd.c udp.c protocol.c console.c devices.c users.c md5.c

mndp: config.h mndp.c protocol.c protocol.h
	gcc -Wall -g -o mndp mndp.c protocol.c
