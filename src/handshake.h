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
#ifndef __HANDSHAKE_H__
#define __HANDSHAKE_H__

#include <gst/gst.h>

#define HANDSHAKE_LENGTH 1536

enum _PexRtmpHandshakeState
{
  HANDSHAKE_START = 0,
  HANDSHAKE_STAGE1 = 1,
  HANDSHAKE_STAGE2 = 2,
  HANDSHAKE_DONE = 3,
};

typedef struct _PexRtmpHandshake PexRtmpHandshake;
typedef enum _PexRtmpHandshakeState PexRtmpHandshakeState;

PexRtmpHandshake * pex_rtmp_handshake_new ();
void pex_rtmp_handshake_free (PexRtmpHandshake * hs);
gboolean pex_rtmp_handshake_process (PexRtmpHandshake * hs,
    const guint8 * data, gint len);

guint8 * pex_rtmp_handshake_get_buffer (PexRtmpHandshake * hs);
guint pex_rtmp_handshake_get_length (PexRtmpHandshake * hs);

gboolean pex_rtmp_handshake_verify_reply (PexRtmpHandshake * hs,
    guint8 reply[HANDSHAKE_LENGTH]);

#endif /* __HANDSHAKE_H__ */
