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
  /* NULL-terminated array of inner-pipeline stage descriptions for this
   * wrapper variant. Set per-subtype from class_data; see
   * wrap_subtype_class_init(). */
  const gchar *const *stages;
} GstPexWrapBinClass;

enum
{
  WRAP_PROP_0,
  WRAP_PROP_AOT,
  WRAP_PROP_SYNC,
  WRAP_PROP_SINGLE_SEGMENT,
};

#define GST_PEX_WRAP_BIN_GET_CLASS(obj) \
  (G_TYPE_INSTANCE_GET_CLASS ((obj), gst_pex_wrap_bin_get_type (), \
      GstPexWrapBinClass))

static GType gst_pex_wrap_bin_get_type (void);
G_DEFINE_TYPE (GstPexWrapBin, gst_pex_wrap_bin, GST_TYPE_BIN);

/* Inner-pipeline stage descriptions for each wrapper variant. Each entry is a
 * single element optionally followed by "prop=value" tokens. */
static const gchar *const wrap_stages_audioconvert[] =
    { "audioconvert", "audioresample", NULL };
static const gchar *const wrap_stages_aacenc[] = { "audioconvert",
  "audioresample", "avenc_aac", "aacparse", "capsfilter caps=audio/mpeg", NULL
};
static const gchar *const wrap_stages_aacdec[] =
    { "avdec_aac", "audioconvert", NULL };
static const gchar *const wrap_stages_h264enc[] = { "videoconvert",
  "x264enc tune=zerolatency speed-preset=ultrafast key-int-max=30",
  "h264parse", "capsfilter caps=video/x-h264", NULL
};
static const gchar *const wrap_stages_h264dec[] =
    { "h264parse", "avdec_h264", "videoconvert", NULL };
static const gchar *const wrap_stages_sync[] = { "identity", NULL };

/* Mapping of plugin feature name -> registered GType name + inner stages. */
typedef struct
{
  const gchar *factory_name;
  const gchar *type_name;
  const gchar *const *stages;
} GstPexWrapDef;

static const GstPexWrapDef wrap_defs[] = {
  {"pexaudioconvert", "GstPexAudioConvert", wrap_stages_audioconvert},
  {"pexaacenc", "GstPexAacEnc", wrap_stages_aacenc},
  {"pexaacdec", "GstPexAacDec", wrap_stages_aacdec},
  {"pexh264enc", "GstPexH264Enc", wrap_stages_h264enc},
  {"pexh264dec", "GstPexH264Dec", wrap_stages_h264dec},
  {"pexsync", "GstPexSync", wrap_stages_sync},
};

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
  GstPexWrapBinClass *klass = GST_PEX_WRAP_BIN_GET_CLASS (self);
  const gchar *const *stages = klass->stages;
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
      GST_ERROR_OBJECT (self, "failed to link stages in '%s'",
          G_OBJECT_TYPE_NAME (self));
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

/* Per-variant class_init: stash the variant's stage list (passed as
 * class_data) on the class so constructed() can build the right inner
 * pipeline. Each wrapper factory is registered as its own GType so that
 * GST_PEX_WRAP_BIN_GET_CLASS()->stages is reliably distinct (sharing a single
 * GType across factories does not work: GstElementClass.elementfactory is
 * stored per-class, not per-instance). */
static void
wrap_subtype_class_init (gpointer klass, gpointer class_data)
{
  ((GstPexWrapBinClass *) klass)->stages = (const gchar * const *) class_data;
}

static GType
wrap_subtype_register (const gchar * type_name, const gchar * const *stages)
{
  GType type = g_type_from_name (type_name);

  if (type == 0) {
    GTypeInfo info = { 0 };
    info.class_size = sizeof (GstPexWrapBinClass);
    info.class_init = wrap_subtype_class_init;
    info.class_data = stages;
    info.instance_size = sizeof (GstPexWrapBin);
    type = g_type_register_static (gst_pex_wrap_bin_get_type (), type_name,
        &info, 0);
  }

  return type;
}

/* ------------------------------------------------------------------------- */

static gboolean
plugin_init (GstPlugin * plugin)
{
  gboolean ret = TRUE;
  guint i;

  for (i = 0; i < G_N_ELEMENTS (wrap_defs); i++) {
    GType type = wrap_subtype_register (wrap_defs[i].type_name,
        wrap_defs[i].stages);
    ret &= gst_element_register (plugin, wrap_defs[i].factory_name,
        GST_RANK_NONE, type);
  }

  ret &= gst_pex_cision_register (plugin);
  ret &= gst_pex_rtmp_bins_register (plugin);

  return ret;
}

GST_PLUGIN_DEFINE (GST_VERSION_MAJOR, GST_VERSION_MINOR,
    pextestelements, "Pexip RTMP server test-support elements",
    plugin_init, "1.0", "LGPL", "pexrtmpserver", "https://pexip.com")
