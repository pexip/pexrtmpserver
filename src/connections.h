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
#ifndef __CONNECTIONS_H__
#define __CONNECTIONS_H__

#include <gst/gst.h>

typedef struct _Connections Connections;

Connections * connections_new ();
void connections_free (Connections * connections);

void connections_add_subscriber (Connections * connections,
    gpointer client, const gchar * path);
gboolean connections_add_publisher (Connections * connections,
    gpointer client, const gchar * path);

GSList * connections_get_subscribers (Connections * connections,
    const gchar * path);
gpointer connections_get_publisher (Connections * connections,
    const gchar * path);

void connections_remove_client (Connections * connections,
    gpointer client, const gchar * path);

#endif /* __CONNECTIONS_H__ */

