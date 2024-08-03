bin_PROGRAMS = mactelnet macping mndp

if HAVE_LIBINTL
LDFLAGS += -lintl
endif

if BUILD_MACTELNETD
sbin_PROGRAMS = mactelnetd
endif

mactelnet_SOURCES = config.h mactelnet.c mactelnet.h protocol.c protocol.h console.c console.h interfaces.c interfaces.h mndp.c mndp.h autologin.c autologin.h extra.h utlist.h mtwei.c mtwei.h
mactelnet_CFLAGS = -DFROM_MACTELNET
mactelnet_LDADD = $(CRYPTO_LIBS)

mactelnetd_SOURCES = config.h mactelnetd.c protocol.c protocol.h interfaces.c interfaces.h console.c console.h users.c users.h extra.h utlist.h mtwei.c mtwei.h
mactelnetd_CFLAGS = -DFROM_MACTELNETD -DUSERSFILE='"$(sysconfdir)/mactelnetd.users"'
mactelnetd_LDADD = $(CRYPTO_LIBS) $(COREFOUNDATION_LIBS) $(SYSTEMCONFIGURATION_LIBS)

savepass_SOURCES = config.h savepass.c mtwei.c mtwei.h users.c users.h extra.h utlist.h
savepass_CFLAGS = -DUSERSFILE='"$(sysconfdir)/mactelnetd.users"'
savepass_LDADD = $(CRYPTO_LIBS)

mndp_SOURCES = config.h mndp.c mndp.h protocol.c protocol.h extra.h

macping_SOURCES = config.h macping.c interfaces.c interfaces.h protocol.c protocol.h extra.h utlist.h

AM_CPPFLAGS = -DLOCALEDIR='"$(localedir)"'

if BUILD_MACTELNETD
mactelnetd-interface.o: interfaces.c
	$(COMPILE) $(mactelnetd_CFLAGS) $(OUTPUT_OPTION) $<
endif

mactelnet-interface.o: interfaces.c
	$(COMPILE) $(mactelnet_CFLAGS) $(OUTPUT_OPTION) $<