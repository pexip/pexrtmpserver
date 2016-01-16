#! /bin/sh

make clean
./autogen.sh
./configure
exec make
