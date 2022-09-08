bin_PROGRAMS = mactelnet macping mndp
sbin_PROGRAMS = mactelnetd

mactelnet_SOURCES = config.h mactelnet.c mactelnet.h protocol.c protocol.h console.c console.h interfaces.c interfaces.h mndp.c mndp.h autologin.c autologin.h extra.h utlist.h mtwei.c mtwei.h
mactelnet_CFLAGS = -DFROM_MACTELNET
mactelnet_LDADD = $(CRYPTO_LIBS)

mactelnetd_SOURCES = config.h mactelnetd.c protocol.c protocol.h interfaces.c interfaces.h console.c console.h users.c users.h extra.h utlist.h
mactelnetd_CFLAGS = -DUSERSFILE='"$(sysconfdir)/mactelnetd.users"'
mactelnetd_LDADD = $(CRYPTO_LIBS)

mndp_SOURCES = config.h mndp.c mndp.h protocol.c protocol.h extra.h

macping_SOURCES = config.h macping.c interfaces.c interfaces.h protocol.c protocol.h extra.h utlist.h

AM_CPPFLAGS = -DLOCALEDIR='"$(localedir)"'
