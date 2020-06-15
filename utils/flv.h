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
#ifndef __FLV_H__
#define __FLV_H__

#include <gst/gst.h>

guint flv_parse_header (const guint8 * data,
    gboolean * have_audio, gboolean * have_video);
guint flv_parse_tag (const guint8 * data, guint size,
    guint8 * packet_type, guint * payload_size, guint * timestamp);
GstBuffer * flv_generate_header (gboolean have_audio, gboolean have_video);
GstBuffer * flv_generate_tag (const guint8 * data,
    gsize size, guint8 id, guint32 timestamp);

#endif /* __FLV_H__ */
