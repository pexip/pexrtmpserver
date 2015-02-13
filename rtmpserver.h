#ifndef __RTMP_SERVER_H__
#define __RTMP_SERVER_H__

#include <glib-object.h>

#define PEX_TYPE_RTMP_SERVER            (pex_rtmp_server_get_type ())
#define PEX_RTMP_SERVER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), PEX_TYPE_RTMP_SERVER, PexRtmpServer))
#define PEX_IS_RTMP_SERVER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), PEX_TYPE_RTMP_SERVER))
#define PEX_RTMP_SERVER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), PEX_TYPE_RTMP_SERVER, PexRtmpServerClass))
#define PEX_IS_RTMP_SERVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), PEX_TYPE_RTMP_SERVER))
#define PEX_RTMP_SERVER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), PEX_TYPE_RTMP_SERVER, PexRtmpServerClass))
#define PEX_RTMP_SERVER_CAST(obj)       ((PexRtmpServer *)(obj))

typedef struct _PexRtmpServer PexRtmpServer;
typedef struct _PexRtmpServerPrivate PexRtmpServerPrivate;
typedef struct _PexRtmpServerClass PexRtmpServerClass;

struct _PexRtmpServer
{
  GObject parent_instance;

  /* instance members */
  PexRtmpServerPrivate * priv;
};

struct _PexRtmpServerClass
{
  GObjectClass parent_class;

  /* class members */
};

GType pex_rtmp_server_get_type (void);

PexRtmpServer * pex_rtmp_server_new (const gchar * application_name,
    gint port, gint ssl_port,
    const gchar * cert, const gchar * key);

gboolean pex_rtmp_server_start (PexRtmpServer * self);
void pex_rtmp_server_stop (PexRtmpServer * self);
void pex_rtmp_server_free (PexRtmpServer * self);
void pex_rtmp_connect_signal(PexRtmpServer * self, gchar * signal_name, gboolean (*callback)(gchar * path));
int pex_rtmp_server_get_queue_size(PexRtmpServer *srv, gchar * path, gboolean publisher);
gboolean pex_rtmp_server_dialout (PexRtmpServer * self, const gchar * path, const gchar * url);

gboolean pex_rtmp_server_parse_url (PexRtmpServer * self, const gchar * url,
    gchar ** protocol, gint * port, gchar ** ip, gchar ** application_name,
    gchar ** path);
gint pex_rtmp_server_tcp_connect (PexRtmpServer * srv,
    const gchar * ip, gint port);

#endif /* __RTMP_SERVER_H__ */
