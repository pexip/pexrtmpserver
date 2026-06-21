/* pexrtmpsrc / pexrtmpsink convenience bins.
 *
 * In pexip/media these are bins that connect a GStreamer pipeline to an
 * in-process PexRtmpServer.  They are rebuilt here purely from the in-tree
 * rtmpserversrc / rtmpserversink elements plus upstream flvmux / flvdemux:
 *
 *   pexrtmpsink:  audio_sink (AAC) --\
 *                                      flvmux ! rtmpserversink (server,path)
 *                 video_sink (H264) -/
 *
 *   pexrtmpsrc:   rtmpserversrc (server,path) ! flvdemux =< audio_src (AAC)
 *                                                            video_src (H264)
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gstpextestelements.h"

#include <gst/gst.h>

/* ===================== pexrtmpsink ======================================== */

typedef struct
{
  GstBin parent;
  GstElement *flvmux;
  GstElement *rtmpsink;
} GstPexRtmpSink;

typedef struct
{
  GstBinClass parent_class;
} GstPexRtmpSinkClass;

enum
{
  SINK_PROP_0,
  SINK_PROP_SERVER,
  SINK_PROP_PATH,
};

static GType gst_pex_rtmp_sink_get_type (void);
G_DEFINE_TYPE (GstPexRtmpSink, gst_pex_rtmp_sink, GST_TYPE_BIN);

static GstStaticPadTemplate sink_audio_template =
GST_STATIC_PAD_TEMPLATE ("audio_sink", GST_PAD_SINK, GST_PAD_REQUEST,
    GST_STATIC_CAPS ("audio/mpeg"));
static GstStaticPadTemplate sink_video_template =
GST_STATIC_PAD_TEMPLATE ("video_sink", GST_PAD_SINK, GST_PAD_REQUEST,
    GST_STATIC_CAPS ("video/x-h264"));

static GstPad *
gst_pex_rtmp_sink_request_new_pad (GstElement * element,
    GstPadTemplate * templ, const gchar * name, const GstCaps * caps)
{
  GstPexRtmpSink *self = (GstPexRtmpSink *) element;
  const gchar *mux_name;
  GstPad *mux_pad, *ghost;

  (void) caps;

  if (g_strcmp0 (GST_PAD_TEMPLATE_NAME_TEMPLATE (templ), "audio_sink") == 0)
    mux_name = "audio";
  else
    mux_name = "video";

  mux_pad = gst_element_request_pad_simple (self->flvmux, mux_name);
  if (mux_pad == NULL) {
    GST_ERROR_OBJECT (self, "could not get flvmux %s pad", mux_name);
    return NULL;
  }

  ghost = gst_ghost_pad_new (name ? name :
      GST_PAD_TEMPLATE_NAME_TEMPLATE (templ), mux_pad);
  gst_object_unref (mux_pad);
  gst_pad_set_active (ghost, TRUE);
  gst_element_add_pad (element, ghost);

  return ghost;
}

static void
gst_pex_rtmp_sink_release_pad (GstElement * element, GstPad * pad)
{
  GstPexRtmpSink *self = (GstPexRtmpSink *) element;
  GstGhostPad *ghost = GST_GHOST_PAD (pad);
  GstPad *target = gst_ghost_pad_get_target (ghost);

  if (target != NULL) {
    gst_element_release_request_pad (self->flvmux, target);
    gst_object_unref (target);
  }
  gst_pad_set_active (pad, FALSE);
  gst_element_remove_pad (element, pad);
}

static void
gst_pex_rtmp_sink_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstPexRtmpSink *self = (GstPexRtmpSink *) object;

  switch (prop_id) {
    case SINK_PROP_SERVER:
      g_object_set (self->rtmpsink, "server", g_value_get_object (value), NULL);
      break;
    case SINK_PROP_PATH:
      g_object_set (self->rtmpsink, "path", g_value_get_string (value), NULL);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_rtmp_sink_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstPexRtmpSink *self = (GstPexRtmpSink *) object;

  switch (prop_id) {
    case SINK_PROP_SERVER:{
      GObject *server = NULL;
      g_object_get (self->rtmpsink, "server", &server, NULL);
      g_value_take_object (value, server);
      break;
    }
    case SINK_PROP_PATH:{
      gchar *path = NULL;
      g_object_get (self->rtmpsink, "path", &path, NULL);
      g_value_take_string (value, path);
      break;
    }
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_rtmp_sink_class_init (GstPexRtmpSinkClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gobject_class->set_property = gst_pex_rtmp_sink_set_property;
  gobject_class->get_property = gst_pex_rtmp_sink_get_property;

  g_object_class_install_property (gobject_class, SINK_PROP_SERVER,
      g_param_spec_object ("server", "Server", "PexRtmpServer to publish to",
          G_TYPE_OBJECT, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, SINK_PROP_PATH,
      g_param_spec_string ("path", "Path", "Path to publish on", NULL,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  element_class->request_new_pad = gst_pex_rtmp_sink_request_new_pad;
  element_class->release_pad = gst_pex_rtmp_sink_release_pad;

  gst_element_class_add_static_pad_template (element_class,
      &sink_audio_template);
  gst_element_class_add_static_pad_template (element_class,
      &sink_video_template);

  gst_element_class_set_static_metadata (element_class,
      "Pexip RTMP sink (test)", "Sink/Network/RTMP",
      "Publishes muxed FLV to an in-process PexRtmpServer",
      "Pexip <support@pexip.com>");
}

static void
gst_pex_rtmp_sink_init (GstPexRtmpSink * self)
{
  self->flvmux = gst_element_factory_make ("flvmux", "mux");
  self->rtmpsink = gst_element_factory_make ("rtmpserversink", "sink");

  if (self->flvmux == NULL || self->rtmpsink == NULL) {
    GST_ERROR_OBJECT (self, "missing flvmux or rtmpserversink");
    return;
  }

  g_object_set (self->flvmux, "streamable", TRUE, NULL);

  gst_bin_add_many (GST_BIN (self), self->flvmux, self->rtmpsink, NULL);
  gst_element_link (self->flvmux, self->rtmpsink);
}

/* ===================== pexrtmpsrc ========================================= */

typedef struct
{
  GstBin parent;
  GstElement *rtmpsrc;
  GstElement *demux;
  GstElement *audio_queue;
  GstElement *video_queue;
  gboolean auto_reconnect;
} GstPexRtmpSrc;

typedef struct
{
  GstBinClass parent_class;
} GstPexRtmpSrcClass;

enum
{
  SRC_PROP_0,
  SRC_PROP_SERVER,
  SRC_PROP_PATH,
  SRC_PROP_AUTO_RECONNECT,
};

static GType gst_pex_rtmp_src_get_type (void);
G_DEFINE_TYPE (GstPexRtmpSrc, gst_pex_rtmp_src, GST_TYPE_BIN);

static GstStaticPadTemplate src_audio_template =
GST_STATIC_PAD_TEMPLATE ("audio_src", GST_PAD_SRC, GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("audio/mpeg"));
static GstStaticPadTemplate src_video_template =
GST_STATIC_PAD_TEMPLATE ("video_src", GST_PAD_SRC, GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-h264"));

static void
gst_pex_rtmp_src_pad_added (GstElement * demux, GstPad * pad,
    GstPexRtmpSrc * self)
{
  GstCaps *caps = gst_pad_get_current_caps (pad);
  GstStructure *s;
  const gchar *name;
  GstElement *queue = NULL;
  GstPad *qpad;

  (void) demux;

  if (caps == NULL)
    caps = gst_pad_query_caps (pad, NULL);
  if (caps == NULL)
    return;

  s = gst_caps_get_structure (caps, 0);
  name = gst_structure_get_name (s);

  if (g_str_has_prefix (name, "audio/"))
    queue = self->audio_queue;
  else if (g_str_has_prefix (name, "video/"))
    queue = self->video_queue;

  gst_caps_unref (caps);

  if (queue == NULL)
    return;

  qpad = gst_element_get_static_pad (queue, "sink");
  if (gst_pad_is_linked (qpad)) {
    gst_object_unref (qpad);
    return;
  }
  if (gst_pad_link (pad, qpad) != GST_PAD_LINK_OK)
    GST_WARNING_OBJECT (self, "failed to link flvdemux pad %s", name);
  gst_object_unref (qpad);
}

static void
gst_pex_rtmp_src_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstPexRtmpSrc *self = (GstPexRtmpSrc *) object;

  switch (prop_id) {
    case SRC_PROP_SERVER:
      g_object_set (self->rtmpsrc, "server", g_value_get_object (value), NULL);
      break;
    case SRC_PROP_PATH:
      g_object_set (self->rtmpsrc, "path", g_value_get_string (value), NULL);
      break;
    case SRC_PROP_AUTO_RECONNECT:
      self->auto_reconnect = g_value_get_boolean (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_rtmp_src_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstPexRtmpSrc *self = (GstPexRtmpSrc *) object;

  switch (prop_id) {
    case SRC_PROP_SERVER:{
      GObject *server = NULL;
      g_object_get (self->rtmpsrc, "server", &server, NULL);
      g_value_take_object (value, server);
      break;
    }
    case SRC_PROP_PATH:{
      gchar *path = NULL;
      g_object_get (self->rtmpsrc, "path", &path, NULL);
      g_value_take_string (value, path);
      break;
    }
    case SRC_PROP_AUTO_RECONNECT:
      g_value_set_boolean (value, self->auto_reconnect);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_rtmp_src_class_init (GstPexRtmpSrcClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gobject_class->set_property = gst_pex_rtmp_src_set_property;
  gobject_class->get_property = gst_pex_rtmp_src_get_property;

  g_object_class_install_property (gobject_class, SRC_PROP_SERVER,
      g_param_spec_object ("server", "Server", "PexRtmpServer to subscribe to",
          G_TYPE_OBJECT, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, SRC_PROP_PATH,
      g_param_spec_string ("path", "Path", "Path to subscribe to", NULL,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, SRC_PROP_AUTO_RECONNECT,
      g_param_spec_boolean ("auto-reconnect", "Auto reconnect",
          "Re-subscribe automatically (compat)", FALSE,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  gst_element_class_add_static_pad_template (element_class,
      &src_audio_template);
  gst_element_class_add_static_pad_template (element_class,
      &src_video_template);

  gst_element_class_set_static_metadata (element_class,
      "Pexip RTMP src (test)", "Source/Network/RTMP",
      "Subscribes to an in-process PexRtmpServer and demuxes FLV",
      "Pexip <support@pexip.com>");
}

static void
gst_pex_rtmp_src_add_ghost (GstPexRtmpSrc * self, GstElement * queue,
    const gchar * name)
{
  GstPad *qpad = gst_element_get_static_pad (queue, "src");
  GstPad *ghost = gst_ghost_pad_new (name, qpad);
  gst_object_unref (qpad);
  gst_pad_set_active (ghost, TRUE);
  gst_element_add_pad (GST_ELEMENT (self), ghost);
}

static void
gst_pex_rtmp_src_init (GstPexRtmpSrc * self)
{
  self->rtmpsrc = gst_element_factory_make ("rtmpserversrc", "src");
  self->demux = gst_element_factory_make ("flvdemux", "demux");
  self->audio_queue = gst_element_factory_make ("queue", "audio_queue");
  self->video_queue = gst_element_factory_make ("queue", "video_queue");

  if (self->rtmpsrc == NULL || self->demux == NULL ||
      self->audio_queue == NULL || self->video_queue == NULL) {
    GST_ERROR_OBJECT (self, "missing rtmpserversrc/flvdemux/queue");
    return;
  }

  /* Don't let the queues stall the pipeline if only one media type flows. */
  g_object_set (self->audio_queue, "leaky", 0, NULL);
  g_object_set (self->video_queue, "leaky", 0, NULL);

  gst_bin_add_many (GST_BIN (self), self->rtmpsrc, self->demux,
      self->audio_queue, self->video_queue, NULL);
  gst_element_link (self->rtmpsrc, self->demux);

  g_signal_connect (self->demux, "pad-added",
      G_CALLBACK (gst_pex_rtmp_src_pad_added), self);

  gst_pex_rtmp_src_add_ghost (self, self->audio_queue, "audio_src");
  gst_pex_rtmp_src_add_ghost (self, self->video_queue, "video_src");
}

/* ========================================================================= */

gboolean
gst_pex_rtmp_bins_register (GstPlugin * plugin)
{
  gboolean ret = TRUE;

  ret &= gst_element_register (plugin, "pexrtmpsink", GST_RANK_NONE,
      gst_pex_rtmp_sink_get_type ());
  ret &= gst_element_register (plugin, "pexrtmpsrc", GST_RANK_NONE,
      gst_pex_rtmp_src_get_type ());

  return ret;
}
