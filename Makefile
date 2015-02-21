LIBS=-lintl
CC?=gcc

# Run this with make LIBS=-lrt if you want to compile on kfreebsd

all: macping mndp mactelnet

clean: distclean

distclean:
	rm -f mactelnet macping mactelnetd mndp
	rm -f po/*.pot
	rm -f *.o

dist: distclean po

install: all install-docs
	install -d $(PREFIX)/bin/
	install mndp $(PREFIX)/bin/
	install macping $(PREFIX)/bin/
	install mactelnet $(PREFIX)/bin/

install-docs:
	install -d $(PREFIX)/share/man/man1/
	install docs/*.1 $(PREFIX)/share/man/man1/

po: po/mactelnet.pot

po/mactelnet.pot: *.c
	xgettext --package-name=mactelnet --msgid-bugs-address=haakon.nessjoen@gmail.com -d mactelnet -C -c_ -k_ -kgettext_noop *.c -o po/mactelnet.pot
	
users.o: users.c users.h
	${CC} -Wall ${CFLAGS} -DUSERSFILE='"/etc/mactelnetd.users"' -c users.c

protocol.o: protocol.c protocol.h
	${CC} -Wall ${CFLAGS} -c protocol.c

interfaces.o: interfaces.c interfaces.h
	${CC} -Wall ${CFLAGS} -c interfaces.c

md5.o: md5.c md5.h
	${CC} -Wall ${CFLAGS} -c md5.c

mactelnet: config.h mactelnet.c mactelnet.h protocol.o console.c console.h interfaces.o md5.o mndp.c
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o mactelnet mactelnet.c protocol.o console.c interfaces.o md5.o -DFROM_MACTELNET mndp.c ${LIBS}

mactelnetd: config.h mactelnetd.c protocol.o interfaces.o console.c console.h users.o users.h md5.o
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o mactelnetd mactelnetd.c protocol.o console.c interfaces.o users.o md5.o ${LIBS}

mndp: config.h mndp.c protocol.o
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o mndp mndp.c protocol.o ${LIBS}

macping: config.h macping.c interfaces.o protocol.o
	${CC} -Wall ${CFLAGS} ${LDFLAGS} -o macping macping.c interfaces.o protocol.o ${LIBS}
