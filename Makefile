OS_NAME := $(shell sh -c 'uname -s 2>/dev/null || echo not')
CC = gcc

BASIC_CFLAGS = -O3 -Wall
BASIC_LDFLAGS =
BASIC_LIBS =

ifeq ($(OS_NAME),Darwin)
    CFLAGS =
    LDFLAGS =
    LIBS = -lintl
else ifeq ($(OS_NAME),Linux)
    CFLAGS = 
    LDFLAGS =
    LIBS =
else ifeq ($(OS_NAME),GNU/kFreeBSD)
    CFLAGS =
    LDFLAGS =
    LIBS = -lrt
else ifeq ($(OS_NAME),FreeBSD)
    CFLAGS =
    LDFLAGS =
    LIBS =
endif

ALL_CFLAGS = $(BASIC_CFLAGS) $(CFLAGS)
ALL_LDFLAGS = $(BASIC_LDFLAGS) $(LDFLAGS)
ALL_LIBS = $(BASIC_LIBS) $(LIBS)

all: macping mndp mactelnet mactelnetd

clean: distclean

distclean:
	rm -f mactelnet macping mactelnetd mndp
	rm -f *.o

potclean:
	rm -f po/*.pot

dist: distclean potclean pot

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

pot: po/mactelnet.pot

po/mactelnet.pot: *.c
	xgettext --package-name=mactelnet --msgid-bugs-address=haakon.nessjoen@gmail.com -d mactelnet -C -c_ -k_ -kgettext_noop *.c -o po/mactelnet.pot

autologin.o: autologin.c autologin.h
	${CC} ${ALL_CFLAGS} -c autologin.c

users.o: users.c users.h
	${CC} ${ALL_CFLAGS} -DUSERSFILE='"/etc/mactelnetd.users"' -c users.c

protocol.o: protocol.c protocol.h
	${CC} ${ALL_CFLAGS} -c protocol.c

interfaces.o: interfaces.c interfaces.h
	${CC} ${ALL_CFLAGS} -c interfaces.c

md5.o: md5.c md5.h
	${CC} ${ALL_CFLAGS} -c md5.c

console.o: console.c
	${CC} ${ALL_CFLAGS} -c console.c

mactelnet: config.h mactelnet.c mactelnet.h protocol.o console.o interfaces.o md5.o mndp.c autologin.o
	${CC} ${ALL_CFLAGS} ${ALL_LDFLAGS} -o mactelnet mactelnet.c protocol.o console.o interfaces.o md5.o autologin.o -DFROM_MACTELNET mndp.c ${ALL_LIBS}

mactelnetd: config.h mactelnetd.c protocol.o interfaces.o console.o users.o users.h md5.o
	${CC} ${ALL_CFLAGS} ${ALL_LDFLAGS} -o mactelnetd mactelnetd.c protocol.o console.o interfaces.o users.o md5.o ${ALL_LIBS}

mndp: config.h mndp.c protocol.o
	${CC} ${ALL_CFLAGS} ${ALL_LDFLAGS} -o mndp mndp.c protocol.o ${ALL_LIBS}

macping: config.h macping.c interfaces.o protocol.o
	${CC} ${ALL_CFLAGS} ${ALL_LDFLAGS} -o macping macping.c interfaces.o protocol.o ${ALL_LIBS}
