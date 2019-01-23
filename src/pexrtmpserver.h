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
#ifndef __PEX_RTMP_SERVER_H__
#define __PEX_RTMP_SERVER_H__

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

PEX_RTMPSERVER_EXPORT
void pex_rtmp_server_add_direct_publisher (PexRtmpServer * srv,
    const gchar * path);
PEX_RTMPSERVER_EXPORT
void pex_rtmp_server_remove_direct_publisher (PexRtmpServer * srv,
    const gchar * path);
PEX_RTMPSERVER_EXPORT
gboolean pex_rtmp_server_publish_flv (PexRtmpServer * srv, const gchar * path,
    GstBuffer * buf);

PEX_RTMPSERVER_EXPORT
void pex_rtmp_server_add_direct_subscriber (PexRtmpServer * srv,
    const gchar * path);
PEX_RTMPSERVER_EXPORT
void pex_rtmp_server_remove_direct_subscriber (PexRtmpServer * srv,
    const gchar * path);
PEX_RTMPSERVER_EXPORT
gboolean pex_rtmp_server_subscribe_flv (PexRtmpServer * srv, const gchar * path,
    GstBuffer ** buf);
PEX_RTMPSERVER_EXPORT
void pex_rtmp_server_flush_subscribe (PexRtmpServer * srv, const gchar * path);

#endif /* __PEX_RTMP_SERVER_H__ */
