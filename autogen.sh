#! /bin/sh
aclocal -I m4 \
&& autoreconf -i \
&& automake --gnu --add-missing
autoconf
