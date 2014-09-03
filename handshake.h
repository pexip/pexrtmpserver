#ifndef __PEX_RTMP_HANDSHAKE_H__
#define __PEX_RTMP_HANDSHAKE_H__

#include <gst/gst.h>

typedef struct _PexRtmpHandshake PexRtmpHandshake;

PexRtmpHandshake * pex_rtmp_handshake_new ();
void pex_rtmp_handshake_free (PexRtmpHandshake * hs);
void pex_rtmp_handshake_process (PexRtmpHandshake * hs,
    const guint8 * data, gint len);

guint8 * pex_rtmp_handshake_get_buffer (PexRtmpHandshake * hs);
guint pex_rtmp_handshake_get_length (PexRtmpHandshake * hs);

#endif /* __PEX_RTMP_HANDSHAKE_H__ */
