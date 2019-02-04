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
#ifndef __TCP_H__
#define __TCP_H__

#include <gst/gst.h>

#ifdef G_OS_WIN32
#  ifdef PEX_RTMPSERVER_EXPORTS
#    define PEX_RTMPSERVER_EXPORT __declspec(dllexport)
#  else
#    define PEX_RTMPSERVER_EXPORT __declspec(dllimport) extern
#  endif
#else
#  define PEX_RTMPSERVER_EXPORT extern
#endif

#define INVALID_FD -1

PEX_RTMPSERVER_EXPORT
gint tcp_connect (const gchar * ip, gint port, gint src_port, gint tcp_syncnt);
PEX_RTMPSERVER_EXPORT
gint tcp_listen (gint port);
PEX_RTMPSERVER_EXPORT
void tcp_disconnect (gint fd);
PEX_RTMPSERVER_EXPORT
gint tcp_accept (gint listen_fd);
PEX_RTMPSERVER_EXPORT
void tcp_set_nonblock (gint fd, gboolean enabled);
PEX_RTMPSERVER_EXPORT
gboolean tcp_is_localhost (gint fd);

#endif /* __TCP_H__ */
