#include "rtmpharness.h"
#include <string.h>
#include <gst/video/video.h>
#include "utils/tcp.h"
#include "pex/tools/pextools.h"

#if defined(_MSC_VER)
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <windows.h>
#else
#  include <sys/socket.h>
#endif

// to get the g_debug messages in the log, simply use:
// (export) G_MESSAGES_DEBUG=all

// to run ssl-tests in gdb use:
// handle SIGPIPE nostop

#define GET_LOCK(h) (&h->lock)
#define GET_COND(h) (&h->cond)
#define LOCK(h)   (g_mutex_lock   (GET_LOCK (h)))
#define UNLOCK(h) (g_mutex_unlock (GET_LOCK (h)))
#define WAIT_UNTIL(h, deadline)  \
(g_cond_wait_until (GET_COND (h), GET_LOCK (h), deadline))
#define SIGNAL(h) (g_cond_signal  (GET_COND (h)))

static int STATIC_PORT = 1935;

void
rtmp_harness_lock (RTMPHarness * h)
{
  LOCK (h);
}

void
rtmp_harness_unlock (RTMPHarness * h)
{
  UNLOCK (h);
}

static gint
count_chars_in_string (const gchar * s, char c)
{
  gint ret;
  for (ret = 0; s[ret]; s[ret] == c ? ret++ : *s++);
  return ret;
}

static gchar *
_get_auth_string (RTMPHarness * h)
{
  if (h->username && h->password)
    return g_strdup_printf ("%s:%s@", h->username, h->password);
  else
    return g_strdup ("");
}

gchar *
rtmp_harness_create_url (RTMPHarness * h,
    const gchar * path, const gchar * protocol, gint port, const gchar * host)
{
  gchar *ret;
  gchar *auth_str = _get_auth_string (h);
  if (count_chars_in_string (host, ':') > 1) {
    ret = g_strdup_printf ("%s://%s[%s]:%d/%s/%s live=1",
        protocol, auth_str, host, port, h->application_name, path);
  } else {
    ret = g_strdup_printf ("%s://%s%s:%d/%s/%s live=1",
        protocol, auth_str, host, port, h->application_name, path);
  }
  g_free (auth_str);
  return ret;
}

gint
rtmp_harness_add_publisher (RTMPHarness * h, const gchar * path)
{
  Publisher *p = g_new0 (Publisher, 1);
  p->path = g_strdup (path);
  p->id = h->publisher_count++;
  g_mutex_init (&p->lock);
  g_cond_init (&p->cond);

  p->rtmpsink = gst_element_factory_make ("pexrtmpsink", NULL);
  g_assert (p->rtmpsink);

  g_object_set (p->rtmpsink, "server", h->server, "path", path, NULL);

  gst_element_set_state (p->rtmpsink, GST_STATE_PLAYING);

  g_hash_table_insert (h->publishers, GINT_TO_POINTER (p->id), p);

  return p->id;
}

void
rtmp_harness_remove_publisher (RTMPHarness * h, gint p_id)
{
  g_hash_table_remove (h->publishers, GINT_TO_POINTER (p_id));
}

/* wrapper function to use correct function signature */
static void
g_thread_join_destroy_notify (gpointer data)
{
  g_thread_join (data);
}

static void
publisher_teardown (Publisher * p)
{
  g_list_free_full (p->push_threads, g_thread_join_destroy_notify);

  gst_element_set_state (p->rtmpsink, GST_STATE_NULL);

  if (p->audio_h)
    gst_harness_teardown (p->audio_h);
  if (p->video_h)
    gst_harness_teardown (p->video_h);

  gst_object_unref (p->rtmpsink);

  g_mutex_clear (&p->lock);
  g_cond_clear (&p->cond);

  g_free (p->path);
  g_free (p);
}

static gint
_get_freq_for_id (gint id)
{
  return 1000 + id * 100;
}

void
rtmp_harness_add_custom_audiosrc (RTMPHarness * h, gint p_id,
    const gchar * launch_str)
{
  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->audio_h = gst_harness_new_with_element (p->rtmpsink, "audio_sink", NULL);
  gst_harness_use_systemclock (p->audio_h);
  gst_harness_play (p->audio_h);

  gst_harness_add_src_parse (p->audio_h, launch_str, TRUE);
}

void
rtmp_harness_add_audiosrc (RTMPHarness * h, gint p_id, RTMPAudioCodec codec)
{
  if (codec == RTMP_AAC) {
    rtmp_harness_add_custom_audiosrc (h, p_id,
        "pexcisionaudiosrc ! pexaudioconvert ! "
        "capsfilter caps=\"audio/x-raw, format=S16LE, rate=48000, channels=2\" "
        "! pexaacenc aot=5");
#if HAVE_SPEEX
  } else if (codec == RTMP_SPEEX) {
    rtmp_harness_add_custom_audiosrc (h, p_id,
        "pexcisionaudiosrc ! pexaudioconvert ! "
        "capsfilter caps=\"audio/x-raw, format=S16LE, rate=16000\" ! speexenc");

#endif /* HAVE_SPEEX */
  } else if (codec == RTMP_ALAW) {
    rtmp_harness_add_custom_audiosrc (h, p_id,
        "pexcisionaudiosrc ! pexaudioconvert ! "
        "capsfilter caps=\"audio/x-raw, format=S16LE, rate=11025, channels=1\" "
        "! alawenc");
  } else {
    g_assert_not_reached ();
  }

  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  GstElement *src = gst_harness_find_element (p->audio_h->src_harness,
      "pexcisionaudiosrc");
  g_object_set (src,
      "mode", 1,
      "freq", (float) _get_freq_for_id (p_id), "samplesperbuffer", 960, NULL);
  gst_object_unref (src);
}

void
rtmp_harness_add_custom_videosrc (RTMPHarness * h, gint p_id,
    const gchar * launch_str)
{
  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->video_h = gst_harness_new_with_element (p->rtmpsink, "video_sink", NULL);
  gst_harness_use_systemclock (p->video_h);
  gst_harness_play (p->video_h);

  gst_harness_add_src_parse (p->video_h, launch_str, TRUE);
}

void
rtmp_harness_add_videosrc (RTMPHarness * h, gint p_id)
{
  rtmp_harness_add_custom_videosrc (h, p_id,
      "pexcisionvideosrc ! "
      "capsfilter caps=\"video/x-raw, width=128, height=72\" ! "
      "pexh264enc ! "
      "capsfilter caps=\"video/x-h264, stream-format=avc, alignment=au\"");

  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  GstElement *src = gst_harness_find_element (p->video_h->src_harness,
      "pexcisionvideosrc");
  g_object_set (src, "id", _get_freq_for_id (p_id), NULL);
  gst_object_unref (src);
}

static void
rtmp_harness_crank_and_push_with_ts_offset (GstHarness * h,
    gint cranks, gint pushes, GstClockTime ts_offset)
{
  GstClockTime ts_base = GST_CLOCK_TIME_NONE;

  gst_harness_play (h->src_harness);

  for (int i = 0; i < cranks; i++)
    g_assert (gst_harness_crank_single_clock_wait (h->src_harness));

  for (int i = 0; i < pushes; i++) {
    GstBuffer *buf = gst_harness_pull (h->src_harness);

    /* Codec setup data (e.g. the Ogg/Speex headers emitted by speexenc) is
     * delivered downstream as HEADER-flagged buffers. It is not a media frame
     * and is carried out-of-band via caps, so skip it: a "push" must refer to
     * an actual media frame for the publisher/subscriber counts to line up.
     *
     * Only pure setup headers must be skipped though. Some encoders (notably
     * x264enc) flag the very first key-frame buffer with GST_BUFFER_FLAG_HEADER
     * even though it carries real, time-stamped media that must be transmitted.
     * A real frame always carries a valid, non-zero duration, whereas a pure
     * setup header carries none. The exact timestamping of the Speex headers
     * differs between a stock speexenc (PTS/duration are GST_CLOCK_TIME_NONE)
     * and the Pexip-patched one (the "speexenc: Don't set lookahead" patch in
     * github.com/pexip/gstreamer, where they come out with PTS == 0 and a zero
     * duration), so rely on the absence of a valid, non-zero duration -- which
     * holds for both -- rather than on the PTS to tell setup headers apart from
     * a HEADER-flagged media frame. */
    while (buf != NULL && GST_BUFFER_FLAG_IS_SET (buf, GST_BUFFER_FLAG_HEADER) &&
        (!GST_CLOCK_TIME_IS_VALID (GST_BUFFER_DURATION (buf)) ||
            GST_BUFFER_DURATION (buf) == 0)) {
      gst_buffer_unref (buf);
      buf = gst_harness_pull (h->src_harness);
    }

    /* Normalise the stream so its first media frame starts at time 0 (plus any
     * requested ts_offset).
     *
     * A stock speexenc leaves the PTS of the very first media frame unset
     * (GST_CLOCK_TIME_NONE) because of the encoder lookahead; the Pexip-patched
     * speexenc ("speexenc: Don't set lookahead") instead emits it with PTS == 0.
     * Upstream x264enc is worse still: to keep DTS non-negative in the presence
     * of reordering it shifts every PTS/DTS by a large constant (1000 hours),
     * so a plain video stream comes out with PTS around 1000h rather than 0.
     *
     * An un-normalised stream is fine on its own, but when two such streams are
     * muxed together (audio + a concurrently pushed video stream) flvmux has to
     * interleave them by running time. With audio sitting near 0 and video near
     * 1000h the aggregator can never line the two pads up, so it stalls and the
     * test deadlocks. Subtracting the first frame's PTS puts every codec on the
     * same zero-based timeline, so audio and video always interleave and the two
     * speexenc builds behave identically. */
    if (!GST_CLOCK_TIME_IS_VALID (GST_BUFFER_PTS (buf)))
      GST_BUFFER_PTS (buf) = 0;

    if (!GST_CLOCK_TIME_IS_VALID (ts_base))
      ts_base = GST_BUFFER_PTS (buf);

    if (GST_BUFFER_PTS (buf) >= ts_base)
      GST_BUFFER_PTS (buf) -= ts_base;
    else
      GST_BUFFER_PTS (buf) = 0;
    GST_BUFFER_PTS (buf) += ts_offset;

    if (GST_CLOCK_TIME_IS_VALID (GST_BUFFER_DTS (buf))) {
      if (GST_BUFFER_DTS (buf) >= ts_base)
        GST_BUFFER_DTS (buf) -= ts_base;
      else
        GST_BUFFER_DTS (buf) = 0;
      GST_BUFFER_DTS (buf) += ts_offset;
    }
    GstFlowReturn ret = gst_harness_push (h, buf);
    if (ret != GST_FLOW_OK)
      break;
  }
}

typedef struct
{
  GstHarness *h;
  gint cranks;
  gint pushes;
  GstClockTime ts_offset;
} AsyncPushCtx;

static gpointer
_async_push_func (AsyncPushCtx * ctx)
{
  rtmp_harness_crank_and_push_with_ts_offset (ctx->h,
      ctx->cranks, ctx->pushes, ctx->ts_offset);
  g_free (ctx);

  return NULL;
}

static GThread *
_push_async (GstHarness * h, gint cranks, gint pushes, GstClockTime ts_offset)
{
  AsyncPushCtx *ctx = g_new0 (AsyncPushCtx, 1);
  ctx->h = h;
  ctx->cranks = cranks;
  ctx->pushes = pushes;
  ctx->ts_offset = ts_offset;
  return g_thread_new ("AsyncPush", (GThreadFunc) _async_push_func, ctx);
}

void
rtmp_harness_set_timestamp_offset (RTMPHarness * h, GstClockTime ts_offset)
{
  GHashTableIter iter;
  gpointer value;

  /* The publisher media is produced by a live source (pexcisionaudiosrc /
   * pexcisionvideosrc are is-live=TRUE so the test can drive them with
   * gst_harness_crank_single_clock_wait), and that liveness propagates down to
   * flvmux. A live GstAggregator paces its output to the pipeline clock: before
   * muxing a buffer it sleeps on the clock until "base_time + running_time".
   * That keeps the audio and video pads interleaving correctly while a test
   * runs in real time, so it must be left in place for normal operation.
   *
   * This setter, however, deliberately jumps the buffer timestamps forward by a
   * large amount (the extended-timestamp test uses 0xffffff ms ~= 4.66 hours) to
   * exercise RTMP's extended-timestamp encoding. With base_time fixed at element
   * start, the aggregator would then sleep ~4.66 hours and the test would
   * dead-lock. Since the timestamps are pushed by hand rather than emitted in
   * real time, compensate by moving flvmux's base_time back by the same amount:
   * "base_time + running_time" stays close to "now", so the pacing wait still
   * orders the pads but returns immediately regardless of the offset size. */
  g_hash_table_iter_init (&iter, h->publishers);
  while (g_hash_table_iter_next (&iter, NULL, &value)) {
    Publisher *p = value;
    GstElement *flvmux = gst_bin_get_by_name (GST_BIN (p->rtmpsink), "mux");

    if (flvmux != NULL) {
      GstClockTime base_time = gst_element_get_base_time (flvmux);

      /* ts_offset only ever grows in practice; guard against underflow. */
      if (GST_CLOCK_TIME_IS_VALID (base_time)) {
        GstClockTimeDiff delta = (GstClockTimeDiff) ts_offset - h->ts_offset;
        if (delta < 0 && (GstClockTime) (-delta) > base_time)
          base_time = 0;
        else
          base_time -= delta;
        gst_element_set_base_time (flvmux, base_time);
      }
      gst_object_unref (flvmux);
    }
  }

  h->ts_offset = ts_offset;
}

void
rtmp_harness_send_audio_async (RTMPHarness * h, gint p_id, gint cranks,
    gint pushes)
{
  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->push_threads = g_list_append (p->push_threads,
      _push_async (p->audio_h, cranks, pushes, h->ts_offset));
}

void
rtmp_harness_send_audio (RTMPHarness * h, gint p_id, gint cranks, gint pushes)
{
  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  rtmp_harness_crank_and_push_with_ts_offset (p->audio_h, cranks, pushes,
      h->ts_offset);
}

void
rtmp_harness_send_video_async (RTMPHarness * h, gint p_id, gint cranks,
    gint pushes)
{
  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->push_threads = g_list_append (p->push_threads,
      _push_async (p->video_h, cranks, pushes, h->ts_offset));
}

void
rtmp_harness_send_video (RTMPHarness * h, gint p_id, gint cranks, gint pushes)
{
  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  rtmp_harness_crank_and_push_with_ts_offset (p->video_h, cranks, pushes,
      h->ts_offset);
}

void
rtmp_harness_request_intra (RTMPHarness * h, gint p_id)
{
  Publisher *p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  gst_pad_push_event (p->video_h->src_harness->sinkpad,
      gst_video_event_new_upstream_force_key_unit (GST_CLOCK_TIME_NONE, TRUE,
          0));
}

 /******* Subscriber ******/

gint
rtmp_harness_add_subscriber (RTMPHarness * h, const gchar * path)
{
  Subscriber *s = g_new0 (Subscriber, 1);
  s->path = g_strdup (path);
  s->id = h->subscriber_count++;
  g_mutex_init (&s->lock);
  g_cond_init (&s->cond);

  s->rtmpsrc = gst_element_factory_make ("pexrtmpsrc", NULL);
  g_assert (s->rtmpsrc);

  g_object_set (s->rtmpsrc, "server", h->server, "path", path, NULL);

  s->audio_h = gst_harness_new_with_element (s->rtmpsrc, NULL, "audio_src");
  s->video_h = gst_harness_new_with_element (s->rtmpsrc, NULL, "video_src");

  gst_harness_use_systemclock (s->audio_h);
  gst_harness_use_systemclock (s->video_h);

  gst_harness_play (s->audio_h);
  gst_harness_play (s->video_h);

  g_hash_table_insert (h->subscribers, GINT_TO_POINTER (s->id), s);

  return s->id;
}

void
rtmp_harness_set_subscriber_auto_reconnect (RTMPHarness * h, gint s_id,
    gboolean auto_reconnect)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  g_assert (s);
  g_object_set (s->rtmpsrc, "auto-reconnect", auto_reconnect, NULL);
}

void
rtmp_harness_remove_subscriber (RTMPHarness * h, gint s_id)
{
  g_hash_table_remove (h->subscribers, GINT_TO_POINTER (s_id));
}

static void
subscriber_teardown (Subscriber * s)
{
  GstState state, pending;
  g_assert (gst_element_set_state (s->rtmpsrc, GST_STATE_NULL) ==
      GST_STATE_CHANGE_SUCCESS);
  g_assert (gst_element_get_state (s->rtmpsrc, &state, &pending, 0) ==
      GST_STATE_CHANGE_SUCCESS);
  g_assert (state == GST_STATE_NULL);
  gst_object_unref (s->rtmpsrc);

  gst_harness_teardown (s->audio_h);
  gst_harness_teardown (s->video_h);

  if (s->freq_list)
    g_value_array_free (s->freq_list);
  if (s->participant_list)
    g_value_array_free (s->participant_list);

  g_mutex_clear (&s->lock);
  g_cond_clear (&s->cond);

  g_free (s->path);
  g_free (s);
}

void
rtmp_harness_add_custom_audiosink (RTMPHarness * h, gint s_id,
    const gchar * launch_str)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  gst_harness_add_sink_parse (s->audio_h, launch_str);
  gst_harness_play (s->audio_h->sink_harness);
}

static void
freq_list_cb (GstElement * sink, GValueArray * freq_list, Subscriber * s)
{
  (void) sink;
  if (s->freq_list)
    g_value_array_free (s->freq_list);
  s->freq_list = g_value_array_copy (freq_list);
}

void
rtmp_harness_add_audiosink (RTMPHarness * h, gint s_id, RTMPAudioCodec codec)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  if (codec == RTMP_AAC) {
    rtmp_harness_add_custom_audiosink (h, s_id,
        "pexaacdec ! pexaudioconvert ! pexcisionaudiosink");
#if HAVE_SPEEX
  } else if (codec == RTMP_SPEEX) {
    rtmp_harness_add_custom_audiosink (h, s_id,
        "speexdec ! pexaudioconvert ! pexcisionaudiosink");
#endif /* HAVE_SPEEX */
  } else if (codec == RTMP_ALAW) {
    rtmp_harness_add_custom_audiosink (h, s_id,
        "alawdec ! pexaudioconvert ! pexcisionaudiosink");
  } else {
    g_assert_not_reached ();
  }
  GstElement *sink = gst_harness_find_element (s->audio_h->sink_harness,
      "pexcisionaudiosink");
  g_signal_connect (sink, "freq-list", G_CALLBACK (freq_list_cb), s);
  /* The analysis window must be small enough that every codec the harness
   * drives can fill it within the modest number of frames a test pushes.
   * speexenc emits short 20 ms / 320-sample frames, so a 16 kHz Speex stream
   * only accumulates ~4-6 frames in the shorter tests; a 1920-sample window
   * would never complete and the freq-list signal would never fire. 960
   * samples is plenty for the Goertzel detector to resolve the 100 Hz-spaced
   * participant tones while staying reachable for all codecs. */
  g_object_set (sink,
      "fft-mag-threshold", -30.0,
      "fft-required-samples", 960, "fft-resolution", 100, NULL);
  gst_object_unref (sink);
}

void
rtmp_harness_add_custom_videosink (RTMPHarness * h, gint s_id,
    const gchar * launch_str)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  gst_harness_add_sink_parse (s->video_h, launch_str);
  gst_harness_play (s->video_h->sink_harness);
}

static void
participant_list_cb (GstElement * sink,
    GValueArray * participant_list, Subscriber * s)
{
  (void) sink;
  if (s->participant_list)
    g_value_array_free (s->participant_list);
  s->participant_list = g_value_array_copy (participant_list);
}

void
rtmp_harness_add_videosink (RTMPHarness * h, gint s_id)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  rtmp_harness_add_custom_videosink (h, s_id,
      "pexh264dec !" "pexcisionvideosink");
  GstElement *sink = gst_harness_find_element (s->video_h->sink_harness,
      "pexcisionvideosink");
  g_signal_connect (sink,
      "participant-list", G_CALLBACK (participant_list_cb), s);
  g_object_set (sink, "participants-hint", 1, NULL);
  gst_object_unref (sink);
}

void
rtmp_harness_recv_audio (RTMPHarness * h, gint s_id, gint pushes)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  for (int i = 0; i < pushes; i++)
    g_assert_cmpint (GST_FLOW_OK, ==, gst_harness_push_to_sink (s->audio_h));
}

void
rtmp_harness_recv_video (RTMPHarness * h, gint s_id, gint pushes)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  for (int i = 0; i < pushes; i++)
    g_assert_cmpint (GST_FLOW_OK, ==, gst_harness_push_to_sink (s->video_h));
}

gboolean
rtmp_harness_verify_recv_audio (RTMPHarness * h, gint s_id, gint p_id)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  if (s->freq_list == NULL)
    return FALSE;
  if (s->freq_list->n_values != 1)
    return FALSE;

  gint expected_id = _get_freq_for_id (p_id);
  gint actual_id = (gint) g_value_get_uint (g_value_array_get_nth (s->freq_list,
          0));
  if (expected_id != actual_id) {
    g_warning ("expected id:%d, got:%d", expected_id, actual_id);
    return FALSE;
  }

  g_value_array_free (s->freq_list);
  s->freq_list = NULL;
  return TRUE;
}

gboolean
rtmp_harness_verify_recv_video (RTMPHarness * h, gint s_id, gint p_id)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  if (s->participant_list == NULL) {
    g_warning ("No participant list!");
    return FALSE;
  }

  if (s->participant_list->n_values != 1) {
    g_warning ("%u n_values instead of 1", s->participant_list->n_values);
    return FALSE;
  }

  gint expected_id = _get_freq_for_id (p_id);
  gint actual_id =
      (gint) g_value_get_uint (g_value_array_get_nth (s->participant_list, 0));
  if (expected_id != actual_id) {
    g_warning ("expected id:%d, got:%d", expected_id, actual_id);
    return FALSE;
  }

  g_value_array_free (s->participant_list);
  s->participant_list = NULL;
  return TRUE;
}

void
rtmp_harness_stop_server (RTMPHarness * h)
{
  pex_rtmp_server_stop (h->server);
}

void
rtmp_harness_start_server (RTMPHarness * h)
{
  pex_rtmp_server_start (h->server);
}

void
rtmp_harness_restart_rtmpsrc (RTMPHarness * h, gint s_id)
{
  Subscriber *s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  gst_element_set_state (s->rtmpsrc, GST_STATE_READY);
  gst_element_set_state (s->rtmpsrc, GST_STATE_PLAYING);
}

static gboolean
rtmp_harness_on_publish (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, GObject * server)
{
  LOCK (h);
  h->notified_publishers++;
  g_debug
      ("got publisher (%d) with client-id %d on server %p for path %s params %s\n",
      client_id, h->notified_publishers, server, path, params);

  UNLOCK (h);

  while (h->block_on_publish)
    g_thread_yield ();

  return h->reject_publishers;
}

static void
rtmp_harness_on_publish_done (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, PexRtmpServerStatus reason,
    GObject * server)
{
  LOCK (h);
  h->notified_publishers--;
  h->publish_done_reason = reason;
  g_debug
      ("lost publisher (%d) with client-id %d on server %p for path %s params %s\n",
      client_id, h->notified_publishers, server, path, params);
  UNLOCK (h);
}

static gboolean
rtmp_harness_on_play (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, GObject * server)
{
  LOCK (h);
  h->notified_subscribers++;
  g_debug
      ("got subscriber (%d) with client-id %d on server %p for path %s params %s\n",
      client_id, h->notified_subscribers, server, path, params);
  UNLOCK (h);

  while (h->block_on_play)
    g_thread_yield ();

  return h->reject_subscribers;
}

static void
rtmp_harness_on_play_done (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, PexRtmpServerStatus reason,
    GObject * server)
{
  LOCK (h);
  h->notified_subscribers--;
  h->play_done_reason = reason;
  g_debug
      ("lost subscriber (%d) with client-id %d on server %p for path %s params %s\n",
      client_id, h->notified_subscribers, server, path, params);
  UNLOCK (h);
}

void
rtmp_harness_wait_for_notified_publishers (RTMPHarness * h, gint publishers)
{
  while (h->notified_publishers != publishers)
    g_usleep (G_USEC_PER_SEC / 100);
}

void
rtmp_harness_wait_for_notified_subscribers (RTMPHarness * h, gint subscribers)
{
  while (h->notified_subscribers != subscribers)
    g_usleep (G_USEC_PER_SEC / 100);
}

gboolean
rtmp_harness_dialout (RTMPHarness * h_from, gint id_from,
    RTMPHarness * h_to, gint id_to, const gchar * protocol,
    const gchar * host, const gchar * ip, gint src_port)
{
  Publisher *p_from = g_hash_table_lookup (h_from->publishers,
      GINT_TO_POINTER (id_from));
  Subscriber *s_to = g_hash_table_lookup (h_to->subscribers,
      GINT_TO_POINTER (id_to));
  g_assert (p_from);
  g_assert (s_to);

  gint port = h_to->port;
  if (g_strcmp0 (protocol, "rtmps") == 0)
    port = h_to->ssl_port;

  gchar *publisher_url = rtmp_harness_create_url (h_to,
      s_to->path, protocol, port, host);
  gboolean result = pex_rtmp_server_dialout (h_from->server, p_from->path,
      publisher_url, ip, src_port);
  g_free (publisher_url);

  return result;
}

gboolean
rtmp_harness_dialin (RTMPHarness * h_from, gint id_from,
    RTMPHarness * h_to, gint id_to, const gchar * protocol,
    const gchar * host, const gchar * ip, gint src_port)
{
  Subscriber *s_from = g_hash_table_lookup (h_from->subscribers,
      GINT_TO_POINTER (id_from));
  Publisher *p_to = g_hash_table_lookup (h_to->publishers,
      GINT_TO_POINTER (id_to));
  g_assert (s_from);
  g_assert (p_to);

  gint port = h_to->port;
  if (g_strcmp0 (protocol, "rtmps") == 0)
    port = h_to->ssl_port;

  gchar *subscriber_url = rtmp_harness_create_url (h_to,
      p_to->path, protocol, port, host);
  gboolean result = pex_rtmp_server_dialin (h_from->server, s_from->path,
      subscriber_url, ip, src_port);
  g_free (subscriber_url);

  return result;
}

void
rtmp_harness_set_stream_id (RTMPHarness * h, gint stream_id)
{
  g_object_set (h->server, "stream-id", stream_id, NULL);
}

void
rtmp_harness_set_chunk_size (RTMPHarness * h, gint chunk_size)
{
  h->chunk_size = chunk_size;
  g_object_set (h->server, "chunk-size", chunk_size, NULL);
}

void
rtmp_harness_set_tcp_syncnt (RTMPHarness * h, gint tcp_syncnt)
{
  g_object_set (h->server, "tcp-syncnt", tcp_syncnt, NULL);
}

gint
rtmp_harness_get_poll_count (RTMPHarness * h)
{
  gint count = 0;

  g_object_get (h->server, "poll-count", &count, NULL);

  return count;
}

gint
rtmp_harness_add_bad_client (RTMPHarness * h)
{
  gint fd;
  tcp_connect (&fd, "localhost", h->port, 0, 0, NULL);

  /* send the first byte of the handshake, then ...nothing... */
  guint8 byte = 0x03;
  send (fd, &byte, 1, 0);
  return fd;
}

gint
rtmp_harness_add_bad_client_ssl (RTMPHarness * h)
{
  gint fd;
  tcp_connect (&fd, "localhost", h->ssl_port, 0, 0, NULL);

  /* Do nothing (not even the TLS handshake) */
  return fd;
}

gint
rtmp_harness_add_bad_server (RTMPHarness * h, gint port)
{
  (void) h;
  return tcp_listen (port);
}

void
rtmp_harness_set_server_auth (RTMPHarness * h,
    const gchar * username, const gchar * password)
{
  g_object_set (h->server, "username", username, "password", password, NULL);
}

void
rtmp_harness_set_dialout_auth (RTMPHarness * h,
    const gchar * username, const gchar * password)
{
  g_free (h->username);
  g_free (h->password);

  h->username = g_strdup (username);
  h->password = g_strdup (password);
}


static RTMPHarness *
rtmp_harness_new_full (const gchar * application_name, gint port, gint ssl_port,
    const gchar * cert, const gchar * key, const gchar * ca,
    const gchar * ciphers)
{
  gchar *certfile, *keyfile, *cafile;
  RTMPHarness *h = g_new0 (RTMPHarness, 1);
  g_mutex_init (&h->lock);
  h->application_name = g_strdup (application_name);
  h->port = port;
  h->ssl_port = ssl_port;
  h->chunk_size = 128;          /* default */

  certfile = g_strdup_printf ("%s/certs/%s", pex_testfile_path (""), cert);
  keyfile = g_strdup_printf ("%s/certs/%s", pex_testfile_path (""), key);
  cafile = g_strdup_printf ("%s/certs/%s", pex_testfile_path (""), ca);

  if (ciphers == NULL) {
    ciphers = "!eNULL:!aNULL:!EXP:!DES:!RC4:!RC2:!IDEA:!ADH:ALL@STRENGTH";
  }

  h->server = pex_rtmp_server_new (application_name, h->port, h->ssl_port,
      certfile, keyfile, cafile, "/etc/ssl/certs", ciphers, FALSE, FALSE);
  g_assert (pex_rtmp_server_start (h->server));

  g_free (cafile);
  g_free (keyfile);
  g_free (certfile);

  h->subscribers =
      g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) subscriber_teardown);
  h->publishers =
      g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) publisher_teardown);

  g_signal_connect_swapped (h->server, "on-play",
      (GCallback) rtmp_harness_on_play, h);
  g_signal_connect_swapped (h->server, "on-play-done",
      (GCallback) rtmp_harness_on_play_done, h);
  g_signal_connect_swapped (h->server, "on-publish",
      (GCallback) rtmp_harness_on_publish, h);
  g_signal_connect_swapped (h->server, "on-publish-done",
      (GCallback) rtmp_harness_on_publish_done, h);

  return h;
}

RTMPHarness *
rtmp_harness_new_with_certs (const gchar * application_name,
    const gchar * cert, const gchar * key, const gchar * ca)
{
  RTMPHarness *h = rtmp_harness_new_full (application_name,
      STATIC_PORT, STATIC_PORT + 1, cert, key, ca, NULL);
  STATIC_PORT += 2;
  return h;
}

RTMPHarness *
rtmp_harness_new_with_ciphers (const gchar * application_name,
    const gchar * ciphers)
{
  RTMPHarness *h = rtmp_harness_new_full (application_name,
      STATIC_PORT, STATIC_PORT + 1, "cert_san.pem", "cert.key",
      "ca.pem", ciphers);
  STATIC_PORT += 2;
  return h;
}

RTMPHarness *
rtmp_harness_new (const gchar * application_name)
{
  return rtmp_harness_new_with_certs (application_name,
      "cert_san.pem", "cert.key", "ca.pem");
}

RTMPHarness *
rtmp_harness_new_with_ports (const gchar * application_name,
    gint port, gint ssl_port)
{
  return rtmp_harness_new_full (application_name, port, ssl_port,
      "cert_san.pem", "cert.key", "ca.pem", NULL);
}

void
rtmp_harness_teardown (RTMPHarness * h)
{
  g_hash_table_destroy (h->publishers);
  g_hash_table_destroy (h->subscribers);

  pex_rtmp_server_stop (h->server);
  g_object_unref (h->server);

  g_mutex_clear (&h->lock);

  g_free (h->username);
  g_free (h->password);
  g_free (h->application_name);
  g_free (h);
}
