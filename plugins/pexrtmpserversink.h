/*
 * Pexip
 * Copyright (C) 2018 Havard Graff <havard@pexip.com>
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
#ifndef __PEX_RTMP_SERVER_SINK_H__
#define __PEX_RTMP_SERVER_SINK_H__

#include <gst/gst.h>
#include <gst/base/gstbasesink.h>

G_BEGIN_DECLS

G_DECLARE_FINAL_TYPE (PexRTMPServerSink, pex_rtmp_server_sink, PEX, RTMP_SERVER_SINK, GstBaseSink)
#define PEX_TYPE_RTMP_SERVER_SINK (pex_rtmp_server_sink_get_type())
#define PEX_RTMP_SERVER_SINK_CAST(obj) ((PexRTMPServerSink *)(obj))

G_END_DECLS

#endif /* __PEX_RTMP_SERVER_SINK_H__ */
