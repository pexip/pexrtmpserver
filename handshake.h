#ifndef __PEX_RTMP_HANDSHAKE_H__
#define __PEX_RTMP_HANDSHAKE_H__

#include <gst/gst.h>

#define HANDSHAKE_LENGTH 1536

typedef struct _PexRtmpHandshake PexRtmpHandshake;

PexRtmpHandshake * pex_rtmp_handshake_new ();
void pex_rtmp_handshake_free (PexRtmpHandshake * hs);
gboolean pex_rtmp_handshake_process (PexRtmpHandshake * hs,
    const guint8 * data, gint len);

guint8 * pex_rtmp_handshake_get_buffer (PexRtmpHandshake * hs);
guint pex_rtmp_handshake_get_length (PexRtmpHandshake * hs);

gboolean pex_rtmp_handshake_verify_reply (PexRtmpHandshake * hs,
    guint8 reply[HANDSHAKE_LENGTH]);

#endif /* __PEX_RTMP_HANDSHAKE_H__ */
