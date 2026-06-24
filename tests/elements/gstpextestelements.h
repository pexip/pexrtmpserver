#ifndef __GST_PEX_TEST_ELEMENTS_H__
#define __GST_PEX_TEST_ELEMENTS_H__

#include <gst/gst.h>

G_BEGIN_DECLS

/* Registers pexcisionaudiosrc/sink and pexcisionvideosrc/sink. */
gboolean gst_pex_cision_register (GstPlugin * plugin);

/* Registers pexrtmpsrc and pexrtmpsink convenience bins. */
gboolean gst_pex_rtmp_bins_register (GstPlugin * plugin);

G_END_DECLS

#endif /* __GST_PEX_TEST_ELEMENTS_H__ */
