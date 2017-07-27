#! /bin/sh

set -e


if [ "$1" = "clean" ]; then
  rm -f aclocal.m4 configure missing install-sh \
        depcomp ltmain.sh config.guess config.sub \
        `find . -name Makefile.in` compile
  rm -rf autom4te.cache
  exit
fi

libtoolize --automake
aclocal -I m4
autoreconf -i
automake --gnu --add-missing
autoconf

LDFLAGS=${LDFLAGS=-lintl}
export LDFLAGS

./configure "$@"
