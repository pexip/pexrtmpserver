/* Compatibility shim: in pexip/media the GStreamer check harness is reachable
 * as a bare "gstharness.h".  Upstream ships it under <gst/check/gstharness.h>,
 * so just forward to that. */
#ifndef __PEX_SHIM_GSTHARNESS_H__
#define __PEX_SHIM_GSTHARNESS_H__

#include <gst/check/gstcheck.h>
#include <gst/check/gstharness.h>

#endif /* __PEX_SHIM_GSTHARNESS_H__ */
