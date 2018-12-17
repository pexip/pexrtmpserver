#ifndef __RTMP_SERVER_H__
#define __RTMP_SERVER_H__

#include <gst/gst.h>

#if defined(_MSC_VER)
#  ifdef PEX_RTMPSERVER_EXPORTS
#    define PEX_RTMPSERVER_EXPORT __declspec(dllexport)
#  else
#    define PEX_RTMPSERVER_EXPORT __declspec(dllimport) extern
#  endif
#else
#  define PEX_RTMPSERVER_EXPORT extern
#endif

PEX_RTMPSERVER_EXPORT
G_DECLARE_FINAL_TYPE (PexRtmpServer, pex_rtmp_server, PEX, RTMP_SERVER, GObject)
#define PEX_TYPE_RTMP_SERVER (pex_rtmp_server_get_type ())
#define PEX_RTMP_SERVER_CAST(obj) ((PexRtmpServer *)(obj))


PEX_RTMPSERVER_EXPORT
PexRtmpServer * pex_rtmp_server_new (const gchar * application_name,
    gint port, gint ssl_port,
    const gchar * cert_file, const gchar * key_file,
    const gchar * ca_cert_file, const gchar * ca_cert_dir,
    const gchar * ciphers, gboolean tls1_enabled,
    gboolean ignore_localhost);

PEX_RTMPSERVER_EXPORT
gboolean pex_rtmp_server_start (PexRtmpServer * self);
PEX_RTMPSERVER_EXPORT
void pex_rtmp_server_stop (PexRtmpServer * self);
PEX_RTMPSERVER_EXPORT
void pex_rtmp_server_free (PexRtmpServer * self);

PEX_RTMPSERVER_EXPORT
gchar * pex_rtmp_server_get_application_for_path (PexRtmpServer * srv,
    gchar * path, gboolean is_publisher);
PEX_RTMPSERVER_EXPORT
gboolean pex_rtmp_server_dialout (PexRtmpServer * self,
    const gchar * path, const gchar * url, const gchar * addresses,
    gint src_port);
PEX_RTMPSERVER_EXPORT
gboolean pex_rtmp_server_dialin (PexRtmpServer * self,
    const gchar * path, const gchar * url, const gchar * addresses,
    gint src_port);
PEX_RTMPSERVER_EXPORT
gboolean pex_rtmp_server_external_connect (PexRtmpServer * self,
    const gchar * path, const gchar * url, const gchar * addresses,
    const gboolean is_publisher, gint src_port);

/* For testing */
PEX_RTMPSERVER_EXPORT
gint pex_rtmp_server_add_listen_fd (PexRtmpServer * srv, gint port);
PEX_RTMPSERVER_EXPORT
gboolean parse_rtmp_url (const gchar * url,
    gchar ** protocol, gint * port, gchar ** ip, gchar ** application_name,
    gchar ** path, gchar ** username, gchar ** password);
PEX_RTMPSERVER_EXPORT
gint tcp_connect (const gchar * ip, gint port, gint src_port, gint tcp_syncnt);
PEX_RTMPSERVER_EXPORT
gint tcp_listen (gint port);

#endif /* __RTMP_SERVER_H__ */
