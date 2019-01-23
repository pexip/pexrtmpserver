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
#ifndef __PARSE_H__
#define __PARSE_H__

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
gboolean parse_rtmp_url (const gchar * url,
    gchar ** protocol, gint * port, gchar ** ip, gchar ** application_name,
    gchar ** path, gchar ** username, gchar ** password);

#endif /* __PARSE_H__ */
