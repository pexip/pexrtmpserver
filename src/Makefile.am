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
