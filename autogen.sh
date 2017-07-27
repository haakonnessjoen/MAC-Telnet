#! /bin/sh

# Clean All
if [ "$1" = "clean" ]; then
  make clean
  rm -f aclocal.m4 compile configure install-sh \
        depcomp ltmain.sh config.guess config.sub \
        `find . -name Makefile.in` compile `find . -name Makefile`
  rm -rf autom4te.cache
  rm -rf src/.deps
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
