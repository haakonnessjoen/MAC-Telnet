dist_man_MANS = mactelnet.1 mndp.1 macping.1

if BUILD_MACTELNETD
dist_man_MANS += mactelnetd.1
CLEANFILES = mactelnetd.1

mactelnetd.1: mactelnetd.1.in
	$(AM_V_GEN)$(SED) -e 's|@sysconfdir[@]|$(sysconfdir)|g' mactelnetd.1.in > $@

endif