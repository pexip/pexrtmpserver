#ifndef __CONNECTIONS_H__
#define __CONNECTIONS_H__

#include <gst/gst.h>

typedef struct _Connections Connections;

Connections * connections_new ();
void connections_free (Connections * connections);

void connections_add_subscriber (Connections * connections,
    gpointer client, const gchar * path);
void connections_add_publisher (Connections * connections,
    gpointer client, const gchar * path);

GSList * connections_get_subscribers (Connections * connections,
    const gchar * path);
gpointer connections_get_publisher (Connections * connections,
    const gchar * path);

void connections_remove_client (Connections * connections,
    gpointer client, const gchar * path);

#endif /* __CONNECTIONS_H__ */

