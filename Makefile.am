lib_LTLIBRARIES = libpexrtmpserver.la
bin_PROGRAMS = rtmpsrv

libpexrtmpserverincludedir = $(includedir)/pex
libpexrtmpserverinclude_HEADERS = rtmpserver.h

noinst_HEADERS = \
	amf.h \
	client.h \
	utils.h \
        rtmp.h

libpexrtmpserver_la_SOURCES = \
	amf.c \
	client.c \
	utils.c \
	rtmpserver.c

libpexrtmpserver_la_CFLAGS = $(GST_CFLAGS)
libpexrtmpserver_la_LIBADD = $(GST_LIBS)
libpexrtmpserver_la_LDFLAGS = $(PEX_ALL_LDFLAGS) -shared

rtmpsrv_SOURCES = main.c
rtmpsrv_CFLAGS = $(GST_CFLAGS)
rtmpsrv_LDADD = $(GST_LIBS) libpexrtmpserver.la

