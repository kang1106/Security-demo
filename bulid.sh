#!/bin/sh

# autoscan
libtoolize
aclocal
autoconf
automake --add-missing
./configure -prefix=$(pwd)
make && make install
