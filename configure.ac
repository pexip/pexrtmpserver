AC_INIT(libpexrtmpserver, 1.0)

AM_PROG_AR
AM_PROG_CC_C_O

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])],
  [AM_DEFAULT_VERBOSITY=1
   AC_SUBST(AM_DEFAULT_VERBOSITY)])

AC_PREREQ([2.62])
LT_PREREQ([2.2.6])
LT_INIT

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.10 -Wall no-define foreign])
CFLAGS+=" -std=gnu99"


PKG_CHECK_MODULES(GST, gstreamer-1.0 >= 0.11.91)
PKG_CHECK_MODULES(OPENSSL, openssl)

GOBJECT_INTROSPECTION_CHECK([1.30.0])

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  pkgconfig/Makefile
  pkgconfig/libpexrtmpserver.pc
])


AC_OUTPUT
