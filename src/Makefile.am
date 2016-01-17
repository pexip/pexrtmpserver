lib_LTLIBRARIES = libpexrtmpserver.la
bin_PROGRAMS = rtmpsrv

libpexrtmpserverincludedir = $(includedir)/rtmpserver
libpexrtmpserverinclude_HEADERS = rtmpserver.h

noinst_HEADERS = \
	amf.h \
	client.h \
	connections.h \
	handshake.h \
	utils.h \
	rtmp.h

libpexrtmpserver_la_SOURCES = \
	amf.c \
	client.c \
	connections.c \
	handshake.c \
	utils.c \
	rtmpserver.c

libpexrtmpserver_la_CFLAGS = $(GST_CFLAGS) $(OPENSSL_CFLAGS)
libpexrtmpserver_la_LIBADD = $(GST_LIBS) $(OPENSSL_LIBS)
libpexrtmpserver_la_LDFLAGS = -no-undefined -shared

rtmpsrv_SOURCES = main.c
rtmpsrv_CFLAGS = $(GST_CFLAGS)
rtmpsrv_LDADD = $(GST_LIBS) libpexrtmpserver.la

#
# GObject introspection
#
# We need --accept-unprefixed because of PseudoTcp and TurnServer.
#
-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir) --warn-all --accept-unprefixed
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

gir_headers = \
	$(top_srcdir)/src/rtmpserver.h

gir_sources = \
	$(top_srcdir)/src/rtmpserver.c

if HAVE_INTROSPECTION
introspection_sources = $(gir_headers) $(gir_sources)

PexRtmp-0.1.gir: libpexrtmpserver.la
PexRtmp_0_1_gir_INCLUDES = GObject-2.0 Gio-2.0 Gst-1.0
PexRtmp_0_1_gir_EXPORT_PACKAGES = pexrtmpserver
PexRtmp_0_1_gir_CFLAGS = $(AM_CFLAGS)
PexRtmp_0_1_gir_LIBS = libpexrtmpserver.la
PexRtmp_0_1_gir_FILES = $(introspection_sources)
INTROSPECTION_GIRS += PexRtmp-0.1.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

endif
