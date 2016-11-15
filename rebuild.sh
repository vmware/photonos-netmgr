#!/bin/sh
make clean && make distclean
aclocal && libtoolize && automake --add-missing && autoreconf && export LIBS=-lmcheck && ./configure  --prefix=/usr --libdir=/usr/lib64
make
