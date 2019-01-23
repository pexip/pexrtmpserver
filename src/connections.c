/* PexRTMPServer
 * Copyright (C) 2019 Pexip
 *  @author: Havard Graff <havard@pexip.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
#include "connections.h"
#include <gst/gst.h>

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

struct _Connections
{
  GHashTable *map;
};

typedef struct
{
  gpointer publisher;
  GSList *subscribers;
} Connection;

static Connection *
connection_new ()
{
  Connection *connection = g_new0 (Connection, 1);
  return connection;
}

static void
connection_free (Connection * connection)
{
  g_slist_free (connection->subscribers);
  g_free (connection);
}

static void
connection_add_subscriber (Connection * connection, gpointer client)
{
  connection->subscribers = g_slist_append (connection->subscribers, client);
}

static void
connection_remove_subscriber (Connection * connection, gpointer client)
{
  connection->subscribers = g_slist_remove (connection->subscribers, client);
}

void
connection_remove_publisher (Connection * connection)
{
  connection->publisher = NULL;

/*
    GSList * subscribers = g_hash_table_lookup (srv->subscriber_lists, gpointer->path);
    for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
      gpointer * subscriber = (gpointer *)walk->data;
      subscriber->ready = FALSE;
    }
*/
}

/******************************************************************/

Connections *
connections_new ()
{
  Connections *connections = g_new0 (Connections, 1);
  connections->map =
      g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) connection_free);
  return connections;
}

void
connections_free (Connections * connections)
{
  g_hash_table_destroy (connections->map);
  g_free (connections);
}

static Connection *
connections_get_connection (Connections * connections, const gchar * path)
{
  Connection *connection = g_hash_table_lookup (connections->map, path);
  if (connection == NULL) {
    connection = connection_new ();
    g_hash_table_insert (connections->map, g_strdup (path), connection);
  }
  return connection;
}

void
connections_add_subscriber (Connections * connections,
    gpointer client, const gchar * path)
{
  Connection *connection = connections_get_connection (connections, path);
  GST_INFO ("adding subscriber %p to path %s", client, path);
  connection_add_subscriber (connection, client);
}

gboolean
connections_add_publisher (Connections * connections,
    gpointer client, const gchar * path)
{
  Connection *connection = connections_get_connection (connections, path);
  if (connection->publisher != NULL) {
    GST_WARNING ("Can't add more then one publisher for a stream");
    return FALSE;
  }
  GST_INFO ("adding publisher %p to path %s", client, path);
  connection->publisher = client;

  return TRUE;
}

GSList *
connections_get_subscribers (Connections * connections, const gchar * path)
{
  Connection *connection = connections_get_connection (connections, path);
  return connection->subscribers;
}

gpointer
connections_get_publisher (Connections * connections, const gchar * path)
{
  Connection *connection = connections_get_connection (connections, path);
  return connection->publisher;
}

void
connections_remove_client (Connections * connections,
    gpointer client, const gchar * path)
{
  Connection *connection = connections_get_connection (connections, path);
  if (connection->publisher == client) {
    connection_remove_publisher (connection);
    return;
  }

  connection_remove_subscriber (connection, client);
}
