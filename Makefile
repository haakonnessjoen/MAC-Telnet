
CC?=gcc

PREFIX	?= /usr/
BINDIR	?= $(PREFIX)/bin/
SBINDIR	?= $(PREFIX)/sbin/
MACDIR	?= $(PREFIX)/share/man/
SYSCONF	?= /etc/

# Run this with make LIBS=-lrt if you want to compile on kfreebsd

all: macping mndp mactelnet mactelnetd

clean: distclean

distclean:
	rm -f mactelnet macping mactelnetd mndp
	rm -f *.o

potclean:
	rm -f po/*.pot

dist: distclean potclean pot

install: all install-docs
	install -d $(DESTDIR)$(BINDIR)
	install mndp $(DESTDIR)$(BINDIR)
	install macping $(DESTDIR)$(BINDIR)
	install mactelnet $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(SBINDIR)
	install -o root mactelnetd $(DESTDIR)$(SBINDIR)
	install -d $(DESTDIR)$(SYSCONF)
	install -m 600 -o root config/mactelnetd.users $(DESTDIR)$(SYSCONF)

install-docs:
	install -d $(DESTDIR)$(MANDIR)/man1/
	install docs/*.1 $(DESTDIR)$(MANDIR)/man1/

pot: po/mactelnet.pot

po/mactelnet.pot: *.c
	xgettext --package-name=mactelnet --msgid-bugs-address=haakon.nessjoen@gmail.com -d mactelnet -C -c_ -k_ -kgettext_noop *.c -o po/mactelnet.pot

autologin.o: autologin.c autologin.h
	${CC} -Wall ${CFLAGS} -c autologin.c

users.o: users.c users.h
	${CC} -Wall ${CFLAGS} -DUSERSFILE='"/etc/mactelnetd.users"' -c users.c

protocol.o: protocol.c protocol.h
	${CC} -Wall ${CFLAGS} -c protocol.c

interfaces.o: interfaces.c interfaces.h
	${CC} -Wall ${CFLAGS} -c interfaces.c

md5.o: md5.c md5.h
	${CC} -Wall ${CFLAGS} -c md5.c

console.o: console.c
	${CC} -Wall ${CFLAGS} -c console.c

mactelnet: config.h mactelnet.c mactelnet.h protocol.o console.o interfaces.o md5.o mndp.c autologin.o
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o mactelnet mactelnet.c protocol.o console.o interfaces.o md5.o autologin.o -DFROM_MACTELNET mndp.c ${LIBS}

mactelnetd: config.h mactelnetd.c protocol.o interfaces.o console.o users.o users.h md5.o
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o mactelnetd mactelnetd.c protocol.o console.o interfaces.o users.o md5.o ${LIBS}

mndp: config.h mndp.c protocol.o
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o mndp mndp.c protocol.o ${LIBS}

macping: config.h macping.c interfaces.o protocol.o
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o macping macping.c interfaces.o protocol.o ${LIBS}
