lib_LTLIBRARIES = libpexrtmpserver.la
bin_PROGRAMS = rtmpsrv

libpexrtmpserverincludedir = $(includedir)/pex
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

libpexrtmpserver_la_CFLAGS = $(GST_CFLAGS) $(GOBJECT_CFLAGS) $(OPENSSL_CFLAGS)
libpexrtmpserver_la_LIBADD = $(GST_LIBS) $(GOBJECT_LIBS) $(OPENSSL_LIBS)
libpexrtmpserver_la_LDFLAGS = $(PEX_ALL_LDFLAGS) -shared

rtmpsrv_SOURCES = main.c
rtmpsrv_CFLAGS = $(GST_CFLAGS)
rtmpsrv_LDADD = $(GST_LIBS) libpexrtmpserver.la

pyrtmpserver_la_SOURCES = pyrtmpserver.c
pyrtmpserver_la_CFLAGS = $(PYTHON_INCLUDES)
pyrtmpserver_la_LDFLAGS = -avoid-version -module
pyrtmpserver_la_LIBADD = libpexrtmpserver.la
