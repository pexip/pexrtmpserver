/* PexRTMPServer test-support GStreamer elements.
 *
 * The rtmp test-suite is shared verbatim with the (private) pexip/media
 * repository.  Over there the media pipelines are built from a number of
 * Pexip-specific GStreamer elements.  None of that proprietary media handling
 * is required to exercise the RTMP server itself, so this plugin provides drop
 * in replacements built purely from upstream GStreamer elements:
 *
 *   pexaudioconvert  -> audioconvert ! audioresample
 *   pexaacenc        -> audioconvert ! audioresample ! avenc_aac ! aacparse
 *   pexaacdec        -> avdec_aac ! audioconvert
 *   pexh264enc       -> videoconvert ! x264enc ! h264parse
 *   pexh264dec       -> h264parse ! avdec_h264 ! videoconvert
 *   pexsync          -> identity            (forwards sync/single-segment)
 *
 * The remaining, test-verification specific elements (pexcision*src/sink) and
 * the convenience bins (pexrtmpsrc/pexrtmpsink) are implemented in their own
 * files.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gstpextestelements.h"

#include <gst/gst.h>

/* ------------------------------------------------------------------------- */
/* Generic wrapper-bin: builds an internal pipeline from a parse description
 * chosen by the factory name, and ghosts its sink/src pads. */

typedef struct
{
  GstBin parent;
  GstElement *inner;
} GstPexWrapBin;

typedef struct
{
  GstBinClass parent_class;
} GstPexWrapBinClass;

enum
{
  WRAP_PROP_0,
  WRAP_PROP_AOT,
  WRAP_PROP_SYNC,
  WRAP_PROP_SINGLE_SEGMENT,
};

static GType gst_pex_wrap_bin_get_type (void);
G_DEFINE_TYPE (GstPexWrapBin, gst_pex_wrap_bin, GST_TYPE_BIN);

/* Returns a NULL-terminated array of factory descriptions (each a single
 * element optionally followed by "prop=value" tokens) for the given wrapper
 * factory name, or NULL if unknown. */
static const gchar **
wrap_stages_for_factory (const gchar * name)
{
  static const gchar *audioconvert[] = { "audioconvert", "audioresample",
    NULL
  };
  static const gchar *aacenc[] = { "audioconvert", "audioresample",
    "avenc_aac", "aacparse", NULL
  };
  static const gchar *aacdec[] = { "avdec_aac", "audioconvert", NULL };
  static const gchar *h264enc[] = { "videoconvert",
    "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=30",
    "h264parse", NULL
  };
  static const gchar *h264dec[] = { "h264parse", "avdec_h264", "videoconvert",
    NULL
  };
  static const gchar *sync[] = { "identity", NULL };

  if (g_strcmp0 (name, "pexaudioconvert") == 0)
    return audioconvert;
  if (g_strcmp0 (name, "pexaacenc") == 0)
    return aacenc;
  if (g_strcmp0 (name, "pexaacdec") == 0)
    return aacdec;
  if (g_strcmp0 (name, "pexh264enc") == 0)
    return h264enc;
  if (g_strcmp0 (name, "pexh264dec") == 0)
    return h264dec;
  if (g_strcmp0 (name, "pexsync") == 0)
    return sync;
  return NULL;
}

/* Build a single element from a "factory prop=value ..." description. */
static GstElement *
make_stage_element (const gchar * desc)
{
  gchar **tokens = g_strsplit (desc, " ", -1);
  GstElement *e = NULL;
  guint i;

  if (tokens == NULL || tokens[0] == NULL)
    goto out;

  e = gst_element_factory_make (tokens[0], NULL);
  if (e == NULL)
    goto out;

  for (i = 1; tokens[i] != NULL; i++) {
    gchar **kv;
    if (tokens[i][0] == '\0')
      continue;
    kv = g_strsplit (tokens[i], "=", 2);
    if (kv[0] != NULL && kv[1] != NULL &&
        g_object_class_find_property (G_OBJECT_GET_CLASS (e), kv[0]) != NULL)
      gst_util_set_object_arg (G_OBJECT (e), kv[0], kv[1]);
    g_strfreev (kv);
  }

out:
  g_strfreev (tokens);
  return e;
}


/* Recursively find a child element that has a given property and set it. */
static gboolean
forward_property (GstBin * bin, const gchar * pname, const GValue * value)
{
  gboolean done = FALSE;
  GstIterator *it = gst_bin_iterate_elements (bin);
  GValue item = G_VALUE_INIT;
  gboolean go = TRUE;

  while (go && !done) {
    switch (gst_iterator_next (it, &item)) {
      case GST_ITERATOR_OK:{
        GstElement *e = g_value_get_object (&item);
        if (GST_IS_BIN (e)) {
          done = forward_property (GST_BIN (e), pname, value);
        } else if (g_object_class_find_property (G_OBJECT_GET_CLASS (e),
                pname) != NULL) {
          g_object_set_property (G_OBJECT (e), pname, value);
          done = TRUE;
        }
        g_value_reset (&item);
        break;
      }
      case GST_ITERATOR_RESYNC:
        gst_iterator_resync (it);
        break;
      default:
        go = FALSE;
        break;
    }
  }
  g_value_unset (&item);
  gst_iterator_free (it);
  return done;
}

static void
gst_pex_wrap_bin_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstPexWrapBin *self = (GstPexWrapBin *) object;

  switch (prop_id) {
    case WRAP_PROP_AOT:
      /* AAC audio object type: not configurable on the upstream encoder we
       * wrap; accepted for command-line compatibility and ignored. */
      break;
    case WRAP_PROP_SYNC:
      forward_property (GST_BIN (self), "sync", value);
      break;
    case WRAP_PROP_SINGLE_SEGMENT:
      forward_property (GST_BIN (self), "single-segment", value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_wrap_bin_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  switch (prop_id) {
    case WRAP_PROP_AOT:
      g_value_set_int (value, 0);
      break;
    case WRAP_PROP_SYNC:
    case WRAP_PROP_SINGLE_SEGMENT:
      g_value_set_boolean (value, FALSE);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_wrap_bin_constructed (GObject * object)
{
  GstPexWrapBin *self = (GstPexWrapBin *) object;
  GstElementFactory *factory = gst_element_get_factory (GST_ELEMENT (self));
  const gchar *fname =
      factory ? GST_OBJECT_NAME (factory) : "pexaudioconvert";
  const gchar **stages = wrap_stages_for_factory (fname);
  GstElement *first = NULL;
  GstElement *last = NULL;
  GstPad *pad, *ghost;
  GstPadTemplate *templ;
  guint i;

  G_OBJECT_CLASS (gst_pex_wrap_bin_parent_class)->constructed (object);

  if (stages == NULL)
    return;

  for (i = 0; stages[i] != NULL; i++) {
    GstElement *e = make_stage_element (stages[i]);
    if (e == NULL) {
      GST_ERROR_OBJECT (self, "failed to create stage '%s'", stages[i]);
      return;
    }
    gst_bin_add (GST_BIN (self), e);
    if (first == NULL)
      first = e;
    if (last != NULL && !gst_element_link (last, e)) {
      GST_ERROR_OBJECT (self, "failed to link stages in '%s'", fname);
      return;
    }
    last = e;
  }

  /* Ghost the first element's sink pad and the last element's src pad. */
  pad = gst_element_get_static_pad (first, "sink");
  if (pad != NULL) {
    templ = gst_element_class_get_pad_template (GST_ELEMENT_GET_CLASS (self),
        "sink");
    ghost = gst_ghost_pad_new_from_template ("sink", pad, templ);
    gst_pad_set_active (ghost, TRUE);
    gst_element_add_pad (GST_ELEMENT (self), ghost);
    gst_object_unref (pad);
  }

  pad = gst_element_get_static_pad (last, "src");
  if (pad != NULL) {
    templ = gst_element_class_get_pad_template (GST_ELEMENT_GET_CLASS (self),
        "src");
    ghost = gst_ghost_pad_new_from_template ("src", pad, templ);
    gst_pad_set_active (ghost, TRUE);
    gst_element_add_pad (GST_ELEMENT (self), ghost);
    gst_object_unref (pad);
  }
}

static void
gst_pex_wrap_bin_class_init (GstPexWrapBinClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gobject_class->set_property = gst_pex_wrap_bin_set_property;
  gobject_class->get_property = gst_pex_wrap_bin_get_property;
  gobject_class->constructed = gst_pex_wrap_bin_constructed;

  g_object_class_install_property (gobject_class, WRAP_PROP_AOT,
      g_param_spec_int ("aot", "AOT", "AAC audio object type (compat, ignored)",
          0, G_MAXINT, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, WRAP_PROP_SYNC,
      g_param_spec_boolean ("sync", "Sync", "Sync on the clock",
          FALSE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, WRAP_PROP_SINGLE_SEGMENT,
      g_param_spec_boolean ("single-segment", "Single segment",
          "Timestamp buffers as one continuous segment",
          FALSE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  gst_element_class_set_static_metadata (element_class,
      "Pexip test wrapper bin", "Generic",
      "Upstream-backed replacement for a Pexip media element",
      "Pexip <support@pexip.com>");

  {
    GstCaps *any = gst_caps_new_any ();
    gst_element_class_add_pad_template (element_class,
        gst_pad_template_new ("sink", GST_PAD_SINK, GST_PAD_ALWAYS, any));
    gst_element_class_add_pad_template (element_class,
        gst_pad_template_new ("src", GST_PAD_SRC, GST_PAD_ALWAYS, any));
    gst_caps_unref (any);
  }
}

static void
gst_pex_wrap_bin_init (GstPexWrapBin * self)
{
  (void) self;
}

/* ------------------------------------------------------------------------- */

static gboolean
plugin_init (GstPlugin * plugin)
{
  gboolean ret = TRUE;
  const gchar *wrappers[] = {
    "pexaudioconvert", "pexaacenc", "pexaacdec",
    "pexh264enc", "pexh264dec", "pexsync", NULL
  };

  for (const gchar **n = wrappers; *n != NULL; n++) {
    ret &= gst_element_register (plugin, *n, GST_RANK_NONE,
        gst_pex_wrap_bin_get_type ());
  }

  ret &= gst_pex_cision_register (plugin);
  ret &= gst_pex_rtmp_bins_register (plugin);

  return ret;
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR, GST_VERSION_MINOR,
    pextestelements, "Pexip RTMP server test-support elements",
    plugin_init, "1.0", "LGPL", "pexrtmpserver", "https://pexip.com")
