#!/bin/sh

autoreconf --force --install --verbose || exit $?
test -n "$NOCONFIGURE" || "$srcdir/configure" "$@"
