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
#include "flv.h"

/*
typedef struct
{
  guint8 packet_type;
  guint8 payload_size[3];
  guint8 timestamp[4];
  guint8 stream_id[3];
} FLVPacketHeader;
*/

static const guint flv_tag_header_size = 11;
static const gchar flv_header[] = {
    'F', 'L', 'V',
    0x01, /* version 1 */
    0x05, /* audio and video */
    0x00, 0x00, 0x00, 0x09, /* 9 bytes header */
    0x00, 0x00, 0x00, 0x00, /* cheating, putting PreviousTagSize0 here */
};

guint
flv_parse_header (const guint8 * data)
{
  /* could use this to "turn on" publishing ? */
  if (data[0] == 'F' && data[1] == 'L' && data[2] == 'V' && data[3] == 0x01)
    return sizeof (flv_header);

  return 0;
}

guint
flv_parse_tag (const guint8 * data, guint size,
    guint8 * packet_type, guint * payload_size, guint32 * timestamp)
{
  if (size < flv_tag_header_size)
    return 0;

  *packet_type = data[0];
  *payload_size = GST_READ_UINT24_BE (&data[1]);
  *timestamp = GST_READ_UINT24_BE (&data[4]) | (data[7] << 24);
  return flv_tag_header_size;
}

GstBuffer *
flv_generate_header ()
{
  guint8 *data = g_malloc (sizeof (flv_header));
  memcpy (data, flv_header, sizeof (flv_header));
  return gst_buffer_new_wrapped (data, sizeof (flv_header));
}

static void
flv_write_tag (guint8 * data,
    guint8 packet_type, guint payload_size, guint32 timestamp)
{
  data[0] = packet_type;
  GST_WRITE_UINT24_BE (&data[1], payload_size);

  GST_WRITE_UINT24_BE (&data[4], timestamp);
  data[7] = (((guint) timestamp) >> 24) & 0xff;

  GST_WRITE_UINT24_BE (&data[8], 0);
}

GstBuffer *
flv_generate_tag (const guint8 * data, gsize size, guint8 id, guint32 timestamp)
{
  guint size_with_header = size + flv_tag_header_size;
  guint tag_size = size_with_header + 4;
  guint8 *tag = g_malloc (tag_size);

  flv_write_tag (tag, id, size, timestamp);

  memcpy (&tag[flv_tag_header_size], data, size);

  /* write the total length (size_with_header) in the last 4 bytes */
  GST_WRITE_UINT32_BE (&tag[size_with_header], size_with_header);

  return gst_buffer_new_wrapped (tag, tag_size);
}