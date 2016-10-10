bin_PROGRAMS = mactelnet macping mndp
sbin_PROGRAMS = mactelnetd

mactelnet_SOURCES = config.h mactelnet.c mactelnet.h protocol.c protocol.h console.c console.h interfaces.c interfaces.h md5.c md5.h mndp.c mndp.h autologin.c autologin.h gettext.h extra.h utlist.h
mactelnet_CFLAGS = -DFROM_MACTELNET

mactelnetd_SOURCES = config.h mactelnetd.c protocol.c protocol.h interfaces.c interfaces.h console.c console.h users.c users.h md5.c md5.h gettext.h extra.h utlist.h
mactelnetd_CFLAGS = -DUSERSFILE='"$(sysconfdir)/mactelnetd.users"'

mndp_SOURCES = config.h mndp.c mndp.h protocol.c protocol.h gettext.h extra.h

macping_SOURCES = config.h macping.c interfaces.c interfaces.h protocol.c protocol.h gettext.h extra.h utlist.h

AM_CPPFLAGS = -DLOCALEDIR='"$(localedir)"' 
