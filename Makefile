
CC?=gcc
CFLAGS+= 

all: macping mndp mactelnet mactelnetd

clean: dist-clean

dist-clean:
	rm -f mactelnet macping mactelnetd mndp
	rm -f *.o

install: all install-docs
	install -d $(DESTDIR)/usr/bin
	install mndp $(DESTDIR)/usr/bin/
	install macping $(DESTDIR)/usr/bin/
	install mactelnet $(DESTDIR)/usr/bin/
	install -d $(DESTDIR)/usr/sbin
	install -o root mactelnetd $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/etc
	install -m 600 -o root config/mactelnetd.users $(DESTDIR)/etc/

install-docs:
	install -d $(DESTDIR)/usr/share/man/man1/
	install docs/*.1 $(DESTDIR)/usr/share/man/man1/

udp.o: udp.c udp.h
	${CC} -Wall ${CFLAGS} -c udp.c

users.o: users.c users.h
	${CC} -Wall ${CFLAGS} -DUSERSFILE='"/etc/mactelnetd.users"' -c users.c

protocol.o: protocol.c protocol.h
	${CC} -Wall ${CFLAGS} -c protocol.c

devices.o: devices.c devices.h
	${CC} -Wall ${CFLAGS} -c devices.c

md5.o: md5.c md5.h
	${CC} -Wall ${CFLAGS} -c md5.c

mactelnet: config.h udp.o mactelnet.c mactelnet.h protocol.o console.c console.h devices.o md5.o
	${CC} -Wall ${CFLAGS} -o mactelnet mactelnet.c udp.o protocol.o console.c devices.o md5.o

mactelnetd: config.h mactelnetd.c udp.o protocol.o devices.o console.c console.h users.o users.h md5.o
	${CC} -Wall ${CFLAGS} -o mactelnetd mactelnetd.c udp.o protocol.o console.c devices.o users.o md5.o

mndp: config.h mndp.c protocol.o
	${CC} -Wall ${CFLAGS} -o mndp mndp.c protocol.o

macping: config.h macping.c udp.o devices.o protocol.o
	${CC} -Wall ${CFLAGS} -o macping macping.c devices.o udp.o protocol.o
