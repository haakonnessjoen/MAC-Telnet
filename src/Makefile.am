bin_PROGRAMS = mactelnet macping mndp
sbin_PROGRAMS = mactelnetd

mactelnet_SOURCES = config.h mactelnet.c mactelnet.h protocol.c console.c interfaces.c md5.c mndp.c autologin.c gettext.h
mactelnet_CFLAGS = -DFROM_MACTELNET

mactelnetd_SOURCES = config.h mactelnetd.c protocol.c interfaces.c console.c users.c users.h md5.c gettext.h
mactelnetd_CFLAGS = -DUSERSFILE='"$(sysconfdir)/mactelnetd.users"'

mndp_SOURCES = config.h mndp.c protocol.c gettext.h

macping_SOURCES = config.h macping.c interfaces.c protocol.c gettext.h

AM_CPPFLAGS = -DLOCALEDIR='"$(localedir)"' 
