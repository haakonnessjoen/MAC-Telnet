dist_man_MANS = mactelnet.1 mndp.1 macping.1

if BUILD_MACTELNETD
dist_man_MANS += mactelnetd.8
EXTRA_DIST = mactelnetd.8.in
CLEANFILES = mactelnetd.8

mactelnetd.8: mactelnetd.8.in
	$(AM_V_GEN)$(SED) -e 's|@sysconfdir[@]|$(sysconfdir)|g' mactelnetd.8.in > $@

endif
