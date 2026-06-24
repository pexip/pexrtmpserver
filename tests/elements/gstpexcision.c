/* pexcision* test verification elements.
 *
 * The pexip/media test-suite uses a handful of "cision" elements to inject and
 * later recover a numeric id through the media pipeline:
 *
 *   pexcisionaudiosrc   - generates a sine tone at a configurable frequency.
 *   pexcisionaudiosink  - recovers the dominant frequency of the audio it
 *                         receives and emits it via the "freq-list" signal.
 *   pexcisionvideosrc   - generates a solid frame whose luma encodes an id.
 *   pexcisionvideosink  - recovers that id from the luma of received frames and
 *                         emits it via the "participant-list" signal.
 *
 * The tone-generation / solid-colour parts are thin wrappers around upstream
 * audiotestsrc / videotestsrc.  The recovery parts are implemented here using a
 * small Goertzel filter (audio) and an average-luma read-out (video) so that
 * the verification semantics of the suite are preserved without any proprietary
 * code.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gstpextestelements.h"

#include <gst/gst.h>
#include <gst/base/gstbasesink.h>
#include <gst/video/video.h>
#include <math.h>
#include <string.h>

/* The id scheme used by the test-suite: id = 1000 + participant * 100. */
#define PEX_ID_BASE 1000
#define PEX_ID_STEP 100
/* Luma step used to encode the participant index into a solid frame. */
#define PEX_LUMA_BASE 20
#define PEX_LUMA_STEP 20

/* ===================== signal helpers ===================================== */

enum
{
  SIGNAL_FREQ_LIST,
  SIGNAL_PARTICIPANT_LIST,
  LAST_SIGNAL
};

/* ===================== pexcisionaudiosrc ================================== */

typedef struct
{
  GstBin parent;
  GstElement *src;
  GstElement *capsfilter;
} GstPexCisionAudioSrc;

typedef struct
{
  GstBinClass parent_class;
} GstPexCisionAudioSrcClass;

enum
{
  AUDIOSRC_PROP_0,
  AUDIOSRC_PROP_MODE,
  AUDIOSRC_PROP_FREQ,
  AUDIOSRC_PROP_SAMPLESPERBUFFER,
};

static GType gst_pex_cision_audio_src_get_type (void);
G_DEFINE_TYPE (GstPexCisionAudioSrc, gst_pex_cision_audio_src, GST_TYPE_BIN);

static void
gst_pex_cision_audio_src_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstPexCisionAudioSrc *self = (GstPexCisionAudioSrc *) object;

  switch (prop_id) {
    case AUDIOSRC_PROP_MODE:
      /* compat only */
      break;
    case AUDIOSRC_PROP_FREQ:
      if (self->src)
        g_object_set (self->src, "freq", (gdouble) g_value_get_float (value),
            NULL);
      break;
    case AUDIOSRC_PROP_SAMPLESPERBUFFER:
      if (self->src)
        g_object_set (self->src, "samplesperbuffer", g_value_get_int (value),
            NULL);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_audio_src_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstPexCisionAudioSrc *self = (GstPexCisionAudioSrc *) object;

  switch (prop_id) {
    case AUDIOSRC_PROP_MODE:
      g_value_set_int (value, 1);
      break;
    case AUDIOSRC_PROP_FREQ:{
      gdouble f = 0;
      if (self->src)
        g_object_get (self->src, "freq", &f, NULL);
      g_value_set_float (value, (gfloat) f);
      break;
    }
    case AUDIOSRC_PROP_SAMPLESPERBUFFER:{
      gint s = 0;
      if (self->src)
        g_object_get (self->src, "samplesperbuffer", &s, NULL);
      g_value_set_int (value, s);
      break;
    }
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_audio_src_class_init (GstPexCisionAudioSrcClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gobject_class->set_property = gst_pex_cision_audio_src_set_property;
  gobject_class->get_property = gst_pex_cision_audio_src_get_property;

  g_object_class_install_property (gobject_class, AUDIOSRC_PROP_MODE,
      g_param_spec_int ("mode", "Mode", "Generator mode (compat)", 0, G_MAXINT,
          1, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, AUDIOSRC_PROP_FREQ,
      g_param_spec_float ("freq", "Frequency", "Tone frequency in Hz", 0,
          G_MAXFLOAT, 440, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class,
      AUDIOSRC_PROP_SAMPLESPERBUFFER,
      g_param_spec_int ("samplesperbuffer", "Samples per buffer",
          "Number of samples per output buffer", 1, G_MAXINT, 1024,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  gst_element_class_set_static_metadata (element_class,
      "Pexip cision audio src (test)", "Source/Audio",
      "Generates a sine tone", "Pexip <support@pexip.com>");
}

static void
gst_pex_cision_audio_src_init (GstPexCisionAudioSrc * self)
{
  GstPad *srcpad, *ghost;
  GstCaps *caps;

  self->src = gst_element_factory_make ("audiotestsrc", "inner");
  if (self->src == NULL) {
    GST_ERROR_OBJECT (self, "missing audiotestsrc");
    return;
  }
  gst_util_set_object_arg (G_OBJECT (self->src), "wave", "sine");
  g_object_set (self->src, "is-live", TRUE, NULL);

  /* Force a fixed, FLV-speex-compatible output format. Downstream
   * pexaudioconvert (audioconvert ! audioresample) adapts to any rate the
   * harness pipelines request via capsfilters. */
  self->capsfilter = gst_element_factory_make ("capsfilter", "outcaps");
  caps = gst_caps_new_simple ("audio/x-raw",
      "rate", G_TYPE_INT, 16000, "channels", G_TYPE_INT, 1, NULL);
  g_object_set (self->capsfilter, "caps", caps, NULL);
  gst_caps_unref (caps);

  gst_bin_add_many (GST_BIN (self), self->src, self->capsfilter, NULL);
  gst_element_link (self->src, self->capsfilter);

  srcpad = gst_element_get_static_pad (self->capsfilter, "src");
  ghost = gst_ghost_pad_new ("src", srcpad);
  gst_object_unref (srcpad);
  gst_pad_set_active (ghost, TRUE);
  gst_element_add_pad (GST_ELEMENT (self), ghost);
}

/* ===================== pexcisionvideosrc ================================== */

typedef struct
{
  GstBin parent;
  GstElement *src;
  gint id;
} GstPexCisionVideoSrc;

typedef struct
{
  GstBinClass parent_class;
} GstPexCisionVideoSrcClass;

enum
{
  VIDEOSRC_PROP_0,
  VIDEOSRC_PROP_ID,
};

static GType gst_pex_cision_video_src_get_type (void);
G_DEFINE_TYPE (GstPexCisionVideoSrc, gst_pex_cision_video_src, GST_TYPE_BIN);

static guint
pex_id_to_luma (gint id)
{
  gint k = (id - PEX_ID_BASE) / PEX_ID_STEP;
  if (k < 0)
    k = 0;
  return (guint) (PEX_LUMA_BASE + k * PEX_LUMA_STEP);
}

static gint
pex_luma_to_id (guint luma)
{
  gint k = (gint) lround (((gdouble) luma - PEX_LUMA_BASE) / PEX_LUMA_STEP);
  if (k < 0)
    k = 0;
  return PEX_ID_BASE + k * PEX_ID_STEP;
}

static void
gst_pex_cision_video_src_apply_id (GstPexCisionVideoSrc * self)
{
  guint luma = pex_id_to_luma (self->id);
  guint color = 0xff000000u | (luma << 16) | (luma << 8) | luma;
  if (self->src)
    g_object_set (self->src, "foreground-color", color, NULL);
}

static void
gst_pex_cision_video_src_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstPexCisionVideoSrc *self = (GstPexCisionVideoSrc *) object;

  switch (prop_id) {
    case VIDEOSRC_PROP_ID:
      self->id = g_value_get_int (value);
      gst_pex_cision_video_src_apply_id (self);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_video_src_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstPexCisionVideoSrc *self = (GstPexCisionVideoSrc *) object;

  switch (prop_id) {
    case VIDEOSRC_PROP_ID:
      g_value_set_int (value, self->id);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_video_src_class_init (GstPexCisionVideoSrcClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);

  gobject_class->set_property = gst_pex_cision_video_src_set_property;
  gobject_class->get_property = gst_pex_cision_video_src_get_property;

  g_object_class_install_property (gobject_class, VIDEOSRC_PROP_ID,
      g_param_spec_int ("id", "Id", "Participant id to embed in the video", 0,
          G_MAXINT, PEX_ID_BASE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  gst_element_class_set_static_metadata (element_class,
      "Pexip cision video src (test)", "Source/Video",
      "Generates a solid frame encoding an id", "Pexip <support@pexip.com>");
}

static void
gst_pex_cision_video_src_init (GstPexCisionVideoSrc * self)
{
  GstPad *srcpad, *ghost;

  self->id = PEX_ID_BASE;
  self->src = gst_element_factory_make ("videotestsrc", "inner");
  if (self->src == NULL) {
    GST_ERROR_OBJECT (self, "missing videotestsrc");
    return;
  }
  gst_util_set_object_arg (G_OBJECT (self->src), "pattern", "solid-color");
  g_object_set (self->src, "is-live", TRUE, NULL);
  gst_pex_cision_video_src_apply_id (self);

  gst_bin_add (GST_BIN (self), self->src);

  srcpad = gst_element_get_static_pad (self->src, "src");
  ghost = gst_ghost_pad_new ("src", srcpad);
  gst_object_unref (srcpad);
  gst_pad_set_active (ghost, TRUE);
  gst_element_add_pad (GST_ELEMENT (self), ghost);
}

/* ===================== pexcisionaudiosink ================================= */

typedef struct
{
  GstBaseSink parent;

  gint rate;
  gint channels;

  gdouble fft_mag_threshold;
  gint fft_required_samples;
  gint fft_resolution;

  gint16 *acc;
  gint acc_len;
  gint acc_cap;
} GstPexCisionAudioSink;

typedef struct
{
  GstBaseSinkClass parent_class;
} GstPexCisionAudioSinkClass;

enum
{
  AUDIOSINK_PROP_0,
  AUDIOSINK_PROP_FFT_MAG_THRESHOLD,
  AUDIOSINK_PROP_FFT_REQUIRED_SAMPLES,
  AUDIOSINK_PROP_FFT_RESOLUTION,
};

static guint audio_signals[LAST_SIGNAL] = { 0 };

static GType gst_pex_cision_audio_sink_get_type (void);
G_DEFINE_TYPE (GstPexCisionAudioSink, gst_pex_cision_audio_sink,
    GST_TYPE_BASE_SINK);

static GstStaticPadTemplate audiosink_template =
GST_STATIC_PAD_TEMPLATE ("sink", GST_PAD_SINK, GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("audio/x-raw, format=(string)S16LE, channels=(int)1, "
        "layout=(string)interleaved, rate=(int)[1, 2147483647]"));

/* Goertzel power for a single frequency. */
static gdouble
goertzel_power (const gint16 * samples, gint n, gint rate, gdouble freq)
{
  gdouble w = 2.0 * G_PI * freq / rate;
  gdouble coeff = 2.0 * cos (w);
  gdouble s0, s1 = 0, s2 = 0;
  gint i;

  for (i = 0; i < n; i++) {
    s0 = samples[i] + coeff * s1 - s2;
    s2 = s1;
    s1 = s0;
  }
  return s1 * s1 + s2 * s2 - coeff * s1 * s2;
}

static void
gst_pex_cision_audio_sink_analyze (GstPexCisionAudioSink * self)
{
  gint n = self->acc_len;
  gint res = self->fft_resolution > 0 ? self->fft_resolution : PEX_ID_STEP;
  gint maxf = self->rate / 2;
  gdouble best_power = 0;
  gint best_freq = 0;
  gdouble total = 0;
  gint f;
  gint i;

  if (n < self->fft_required_samples || self->rate <= 0)
    return;

  for (i = 0; i < n; i++)
    total += (gdouble) self->acc[i] * self->acc[i];
  if (total <= 0)
    return;

  for (f = res; f <= maxf; f += res) {
    gdouble p = goertzel_power (self->acc, n, self->rate, (gdouble) f);
    if (p > best_power) {
      best_power = p;
      best_freq = f;
    }
  }

  if (best_freq > 0) {
    /* Normalised peak magnitude in dB; gate weak/noisy signals. */
    gdouble db = 10.0 * log10 (best_power / (total * n));
    if (db >= self->fft_mag_threshold) {
      GValueArray *arr = g_value_array_new (1);
      GValue v = G_VALUE_INIT;
      g_value_init (&v, G_TYPE_UINT);
      g_value_set_uint (&v, (guint) best_freq);
      g_value_array_append (arr, &v);
      g_value_unset (&v);
      g_signal_emit (self, audio_signals[SIGNAL_FREQ_LIST], 0, arr);
      g_value_array_free (arr);
    }
  }

  /* Reset the accumulator for the next window. */
  self->acc_len = 0;
}

static gboolean
gst_pex_cision_audio_sink_set_caps (GstBaseSink * sink, GstCaps * caps)
{
  GstPexCisionAudioSink *self = (GstPexCisionAudioSink *) sink;
  GstStructure *s = gst_caps_get_structure (caps, 0);

  if (!gst_structure_get_int (s, "rate", &self->rate))
    self->rate = 0;
  if (!gst_structure_get_int (s, "channels", &self->channels))
    self->channels = 1;
  return TRUE;
}

static GstFlowReturn
gst_pex_cision_audio_sink_render (GstBaseSink * sink, GstBuffer * buffer)
{
  GstPexCisionAudioSink *self = (GstPexCisionAudioSink *) sink;
  GstMapInfo map;
  gint nsamples;

  if (!gst_buffer_map (buffer, &map, GST_MAP_READ))
    return GST_FLOW_OK;

  nsamples = map.size / sizeof (gint16);
  if (self->acc_len + nsamples > self->acc_cap) {
    self->acc_cap = self->acc_len + nsamples;
    self->acc = g_realloc (self->acc, self->acc_cap * sizeof (gint16));
  }
  memcpy (self->acc + self->acc_len, map.data, nsamples * sizeof (gint16));
  self->acc_len += nsamples;
  gst_buffer_unmap (buffer, &map);

  if (self->acc_len >= self->fft_required_samples)
    gst_pex_cision_audio_sink_analyze (self);

  return GST_FLOW_OK;
}

static void
gst_pex_cision_audio_sink_finalize (GObject * object)
{
  GstPexCisionAudioSink *self = (GstPexCisionAudioSink *) object;
  g_free (self->acc);
  G_OBJECT_CLASS (gst_pex_cision_audio_sink_parent_class)->finalize (object);
}

static void
gst_pex_cision_audio_sink_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstPexCisionAudioSink *self = (GstPexCisionAudioSink *) object;

  switch (prop_id) {
    case AUDIOSINK_PROP_FFT_MAG_THRESHOLD:
      self->fft_mag_threshold = g_value_get_double (value);
      break;
    case AUDIOSINK_PROP_FFT_REQUIRED_SAMPLES:
      self->fft_required_samples = g_value_get_int (value);
      break;
    case AUDIOSINK_PROP_FFT_RESOLUTION:
      self->fft_resolution = g_value_get_int (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_audio_sink_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstPexCisionAudioSink *self = (GstPexCisionAudioSink *) object;

  switch (prop_id) {
    case AUDIOSINK_PROP_FFT_MAG_THRESHOLD:
      g_value_set_double (value, self->fft_mag_threshold);
      break;
    case AUDIOSINK_PROP_FFT_REQUIRED_SAMPLES:
      g_value_set_int (value, self->fft_required_samples);
      break;
    case AUDIOSINK_PROP_FFT_RESOLUTION:
      g_value_set_int (value, self->fft_resolution);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_audio_sink_class_init (GstPexCisionAudioSinkClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);
  GstBaseSinkClass *basesink_class = GST_BASE_SINK_CLASS (klass);

  gobject_class->set_property = gst_pex_cision_audio_sink_set_property;
  gobject_class->get_property = gst_pex_cision_audio_sink_get_property;
  gobject_class->finalize = gst_pex_cision_audio_sink_finalize;

  basesink_class->set_caps = gst_pex_cision_audio_sink_set_caps;
  basesink_class->render = gst_pex_cision_audio_sink_render;

  g_object_class_install_property (gobject_class,
      AUDIOSINK_PROP_FFT_MAG_THRESHOLD,
      g_param_spec_double ("fft-mag-threshold", "FFT magnitude threshold",
          "Minimum normalised peak magnitude (dB) to report a frequency",
          -G_MAXDOUBLE, G_MAXDOUBLE, -30.0,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class,
      AUDIOSINK_PROP_FFT_REQUIRED_SAMPLES,
      g_param_spec_int ("fft-required-samples", "FFT required samples",
          "Number of samples to accumulate before analysing", 1, G_MAXINT,
          1024, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (gobject_class, AUDIOSINK_PROP_FFT_RESOLUTION,
      g_param_spec_int ("fft-resolution", "FFT resolution",
          "Frequency search step in Hz", 1, G_MAXINT, PEX_ID_STEP,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  audio_signals[SIGNAL_FREQ_LIST] = g_signal_new ("freq-list",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
      G_TYPE_NONE, 1, G_TYPE_VALUE_ARRAY);

  gst_element_class_add_static_pad_template (element_class,
      &audiosink_template);
  gst_element_class_set_static_metadata (element_class,
      "Pexip cision audio sink (test)", "Sink/Audio",
      "Recovers the dominant frequency of received audio",
      "Pexip <support@pexip.com>");
}

static void
gst_pex_cision_audio_sink_init (GstPexCisionAudioSink * self)
{
  self->fft_mag_threshold = -30.0;
  self->fft_required_samples = 1024;
  self->fft_resolution = PEX_ID_STEP;
  self->channels = 1;
}

/* ===================== pexcisionvideosink ================================= */

typedef struct
{
  GstBaseSink parent;
  GstVideoInfo info;
  gboolean have_info;
  gint participants_hint;
} GstPexCisionVideoSink;

typedef struct
{
  GstBaseSinkClass parent_class;
} GstPexCisionVideoSinkClass;

enum
{
  VIDEOSINK_PROP_0,
  VIDEOSINK_PROP_PARTICIPANTS_HINT,
};

static guint video_signals[LAST_SIGNAL] = { 0 };

static GType gst_pex_cision_video_sink_get_type (void);
G_DEFINE_TYPE (GstPexCisionVideoSink, gst_pex_cision_video_sink,
    GST_TYPE_BASE_SINK);

static GstStaticPadTemplate videosink_template =
GST_STATIC_PAD_TEMPLATE ("sink", GST_PAD_SINK, GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-raw, format=(string)I420"));

static gboolean
gst_pex_cision_video_sink_set_caps (GstBaseSink * sink, GstCaps * caps)
{
  GstPexCisionVideoSink *self = (GstPexCisionVideoSink *) sink;
  self->have_info = gst_video_info_from_caps (&self->info, caps);
  return self->have_info;
}

static GstFlowReturn
gst_pex_cision_video_sink_render (GstBaseSink * sink, GstBuffer * buffer)
{
  GstPexCisionVideoSink *self = (GstPexCisionVideoSink *) sink;
  GstVideoFrame frame;
  guint64 sum = 0;
  guint count = 0;
  gint x, y, w, h, stride;
  const guint8 *data;
  gint id;
  GValueArray *arr;
  GValue v = G_VALUE_INIT;

  if (!self->have_info)
    return GST_FLOW_OK;

  if (!gst_video_frame_map (&frame, &self->info, buffer, GST_MAP_READ))
    return GST_FLOW_OK;

  w = GST_VIDEO_FRAME_COMP_WIDTH (&frame, 0);
  h = GST_VIDEO_FRAME_COMP_HEIGHT (&frame, 0);
  stride = GST_VIDEO_FRAME_COMP_STRIDE (&frame, 0);
  data = GST_VIDEO_FRAME_COMP_DATA (&frame, 0);

  /* Sample the centre region to avoid any edge artefacts from encoding. */
  for (y = h / 4; y < (3 * h) / 4; y++) {
    for (x = w / 4; x < (3 * w) / 4; x++) {
      sum += data[y * stride + x];
      count++;
    }
  }
  gst_video_frame_unmap (&frame);

  if (count == 0)
    return GST_FLOW_OK;

  {
    gdouble luma = (gdouble) sum / count;

    /* The id is encoded as a full-range RGB grey value at the source, but the
     * round-trip through the H.264 encoder/decoder delivers studio-swing
     * (limited range, 16..235) luma here.  Expand it back to the full 0..255
     * range before decoding so the recovered id matches the one embedded by
     * pexcisionvideosrc; otherwise the systematic 16/219 scaling shifts every
     * reading by roughly one id step. */
    if (self->info.colorimetry.range == GST_VIDEO_COLOR_RANGE_16_235) {
      luma = (luma - 16.0) * 255.0 / 219.0;
      if (luma < 0.0)
        luma = 0.0;
      else if (luma > 255.0)
        luma = 255.0;
    }

    id = pex_luma_to_id ((guint) (luma + 0.5));
  }

  arr = g_value_array_new (1);
  g_value_init (&v, G_TYPE_UINT);
  g_value_set_uint (&v, (guint) id);
  g_value_array_append (arr, &v);
  g_value_unset (&v);
  g_signal_emit (self, video_signals[SIGNAL_PARTICIPANT_LIST], 0, arr);
  g_value_array_free (arr);

  return GST_FLOW_OK;
}

static void
gst_pex_cision_video_sink_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstPexCisionVideoSink *self = (GstPexCisionVideoSink *) object;

  switch (prop_id) {
    case VIDEOSINK_PROP_PARTICIPANTS_HINT:
      self->participants_hint = g_value_get_int (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_video_sink_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstPexCisionVideoSink *self = (GstPexCisionVideoSink *) object;

  switch (prop_id) {
    case VIDEOSINK_PROP_PARTICIPANTS_HINT:
      g_value_set_int (value, self->participants_hint);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_pex_cision_video_sink_class_init (GstPexCisionVideoSinkClass * klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);
  GstElementClass *element_class = GST_ELEMENT_CLASS (klass);
  GstBaseSinkClass *basesink_class = GST_BASE_SINK_CLASS (klass);

  gobject_class->set_property = gst_pex_cision_video_sink_set_property;
  gobject_class->get_property = gst_pex_cision_video_sink_get_property;

  basesink_class->set_caps = gst_pex_cision_video_sink_set_caps;
  basesink_class->render = gst_pex_cision_video_sink_render;

  g_object_class_install_property (gobject_class,
      VIDEOSINK_PROP_PARTICIPANTS_HINT,
      g_param_spec_int ("participants-hint", "Participants hint",
          "Expected number of participants (compat)", 0, G_MAXINT, 1,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  video_signals[SIGNAL_PARTICIPANT_LIST] = g_signal_new ("participant-list",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL, NULL,
      G_TYPE_NONE, 1, G_TYPE_VALUE_ARRAY);

  gst_element_class_add_static_pad_template (element_class,
      &videosink_template);
  gst_element_class_set_static_metadata (element_class,
      "Pexip cision video sink (test)", "Sink/Video",
      "Recovers an id from the luma of received frames",
      "Pexip <support@pexip.com>");
}

static void
gst_pex_cision_video_sink_init (GstPexCisionVideoSink * self)
{
  self->participants_hint = 1;
}

/* ========================================================================= */

gboolean
gst_pex_cision_register (GstPlugin * plugin)
{
  gboolean ret = TRUE;

  ret &= gst_element_register (plugin, "pexcisionaudiosrc", GST_RANK_NONE,
      gst_pex_cision_audio_src_get_type ());
  ret &= gst_element_register (plugin, "pexcisionvideosrc", GST_RANK_NONE,
      gst_pex_cision_video_src_get_type ());
  ret &= gst_element_register (plugin, "pexcisionaudiosink", GST_RANK_NONE,
      gst_pex_cision_audio_sink_get_type ());
  ret &= gst_element_register (plugin, "pexcisionvideosink", GST_RANK_NONE,
      gst_pex_cision_video_sink_get_type ());

  return ret;
}
