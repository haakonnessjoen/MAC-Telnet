#! /bin/sh
aclocal \
&& autoreconf -i \
&& automake --gnu --add-missing
autoconf
