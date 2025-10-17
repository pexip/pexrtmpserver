#include "rtmpharness.h"
#include <string.h>
#include <gst/video/video.h>
#include <sys/socket.h>

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

static void
_rtmpsink_connected_cb (GstElement * rtmpsink, GParamSpec * pspec, Publisher * p)
{
  (void)pspec;
  LOCK (p);
  g_object_get (rtmpsink, "connected", &p->rtmpsink_connected, NULL);
  g_debug ("******* RTMPSINK WAS %sCONNECTED *******\n",
      p->rtmpsink_connected ? "" : "DIS");
  SIGNAL (p);
  UNLOCK (p);
}

static gint
count_chars_in_string (const gchar * s, char c)
{
  gint ret;
  for (ret = 0; s[ret]; s[ret]==c ? ret++ : *s++);
  return ret;
}

static gchar *
rtmp_harness_get_publisher_url (RTMPHarness * h,
    const gchar * path, const gchar * protocol, gint port,
    const gchar * host)
{
  gchar * ret;
  if (count_chars_in_string (host, ':') > 1) {
    ret = g_strdup_printf ("%s://[%s]:%d/%s/%s live=1",
        protocol, host, port, h->application_name, path);
  } else {
    ret = g_strdup_printf ("%s://%s:%d/%s/%s live=1",
        protocol, host, port, h->application_name, path);
  }
  return ret;
}

static gint
rtmp_harness_add_publisher_full (RTMPHarness * h,
    const gchar * path, const gchar * protocol, gint port)
{
  Publisher * p = g_new0 (Publisher, 1);
  p->path = g_strdup (path);
  p->id = h->publisher_count++;
  g_mutex_init (&p->lock);
  g_cond_init (&p->cond);

  gchar * publisher_url = rtmp_harness_get_publisher_url (h,
      path, protocol, port, "localhost");
  gchar * pipeline = g_strdup_printf (
      "flvmux streamable=1 ! rtmpsink location=\"%s\"", publisher_url);
  g_free (publisher_url);

  p->h = gst_harness_new_parse (pipeline);
  g_free (pipeline);
  p->flvmux = gst_harness_find_element (p->h, "flvmux");
  GstElement * rtmpsink = gst_harness_find_element (p->h, "rtmpsink");
  g_signal_connect (rtmpsink,
      "notify::connected", G_CALLBACK (_rtmpsink_connected_cb), p);
  gst_object_unref (rtmpsink);

  gst_harness_play (p->h);

  g_hash_table_insert (h->publishers, GINT_TO_POINTER (p->id), p);

  return p->id;
}

gint
rtmp_harness_add_publisher (RTMPHarness * h, const gchar * path)
{
  return rtmp_harness_add_publisher_full (h, path, "rtmp", h->port);
}

gint
rtmp_harness_add_publisher_ssl (RTMPHarness * h, const gchar * path)
{
  return rtmp_harness_add_publisher_full (h, path, "rtmps", h->ssl_port);
}

void
rtmp_harness_remove_publisher (RTMPHarness * h, gint p_id)
{
  g_hash_table_remove (h->publishers, GINT_TO_POINTER (p_id));
}

static void
publisher_teardown (Publisher * p)
{
  gst_object_unref (p->flvmux);
  gst_harness_teardown (p->h);

  g_list_free_full (p->push_threads, (GDestroyNotify)g_thread_join);

  if (p->audio_h)
    gst_harness_teardown (p->audio_h);
  if (p->video_h)
    gst_harness_teardown (p->video_h);

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
rtmp_harness_add_custom_audiosrc (RTMPHarness * h, gint p_id, const gchar * launch_str)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->audio_h = gst_harness_new_with_element (p->flvmux, "audio", NULL);
  gst_harness_play (p->audio_h);

  p->audio_h->src_harness = gst_harness_new_parse (launch_str);
  gst_harness_use_testclock (p->audio_h->src_harness);
}

void
rtmp_harness_add_audiosrc (RTMPHarness * h, gint p_id, RTMPAudioCodec codec)
{
   if (codec == RTMP_SPEEX) {
     rtmp_harness_add_custom_audiosrc (h, p_id,
        "pexcisionaudiosrc ! pexaudioconvert ! "
        "capsfilter caps=\"audio/x-raw-int, rate=16000\" ! speexenc");
  } else if (codec == RTMP_AAC) {
     rtmp_harness_add_custom_audiosrc (h, p_id,
        "pexcisionaudiosrc ! pexaudioconvert ! "
        "capsfilter caps=\"audio/x-raw-int, rate=48000, channels=2\" ! pexaacenc aot=5");
  } else {
    g_assert_not_reached ();
  }

  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  GstElement * src = gst_harness_find_element (p->audio_h->src_harness, "pexcisionaudiosrc");
  g_object_set (src,
      "mode", 1,
      "freq", (float)_get_freq_for_id (p_id),
      "samplesperbuffer", 960,
      NULL);
  gst_object_unref (src);
}

void
rtmp_harness_add_custom_videosrc (RTMPHarness * h, gint p_id, const gchar * launch_str)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->video_h = gst_harness_new_with_element (p->flvmux, "video", NULL);
  gst_harness_play (p->video_h);

  p->video_h->src_harness = gst_harness_new_parse (launch_str);
  gst_harness_use_testclock (p->video_h->src_harness);
}

void
rtmp_harness_add_videosrc (RTMPHarness * h, gint p_id)
{
  rtmp_harness_add_custom_videosrc (h, p_id,
      "pexcisionvideosrc ! "
      "pexh264enc ! "
      "capsfilter caps=\"video/x-h264, stream-format=byte-stream, alignment=nal\" ! "
      "h264parse ! "
      "capsfilter caps=\"video/x-h264, stream-format=(string)avc, alignment=(string)au\"");

  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  GstElement * src = gst_harness_find_element (p->video_h->src_harness, "pexcisionvideosrc");
  g_object_set (src, "id", _get_freq_for_id (p_id), NULL);
  gst_object_unref (src);
}

static void
rtmp_harness_crank_and_push_with_ts_offset (GstHarness * h,
    gint cranks, gint pushes, GstClockTime ts_offset)
{
  gst_harness_play (h->src_harness);

  for (int i = 0; i < cranks; i++)
    g_assert (gst_harness_crank_single_clock_wait (h->src_harness));

  for (int i = 0; i < pushes; i++) {
    GstBuffer * buf = gst_harness_pull (h->src_harness);
    GST_BUFFER_TIMESTAMP (buf) += ts_offset;
    GstFlowReturn ret = gst_harness_push (h, buf);
    if (ret != GST_FLOW_OK)
      break;
  }
}

typedef struct
{
  GstHarness * h;
  gint cranks;
  gint pushes;
  GstClockTime ts_offset;
} AsyncPushCtx;

static void
_async_push_func (AsyncPushCtx * ctx)
{
  rtmp_harness_crank_and_push_with_ts_offset (ctx->h,
      ctx->cranks, ctx->pushes, ctx->ts_offset);
  g_free (ctx);
}

static GThread *
_push_async (GstHarness * h, gint cranks, gint pushes, GstClockTime ts_offset)
{
  AsyncPushCtx * ctx = g_new0 (AsyncPushCtx, 1);
  ctx->h = h;
  ctx->cranks = cranks;
  ctx->pushes = pushes;
  ctx->ts_offset = ts_offset;
  return g_thread_new ("AsyncPush", (GThreadFunc)_async_push_func, ctx);
}

void
rtmp_harness_set_timestamp_offset (RTMPHarness * h, GstClockTime ts_offset)
{
  h->ts_offset = ts_offset;
}

void
rtmp_harness_send_audio_async (RTMPHarness * h, gint p_id, gint cranks, gint pushes)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->push_threads = g_list_append (p->push_threads,
      _push_async (p->audio_h, cranks, pushes, h->ts_offset));
}

void
rtmp_harness_send_audio (RTMPHarness * h, gint p_id, gint cranks, gint pushes)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  rtmp_harness_crank_and_push_with_ts_offset (p->audio_h, cranks, pushes, h->ts_offset);
}

void
rtmp_harness_send_video_async (RTMPHarness * h, gint p_id, gint cranks, gint pushes)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  p->push_threads = g_list_append (p->push_threads,
      _push_async (p->video_h, cranks, pushes, h->ts_offset));
}

void
rtmp_harness_send_video (RTMPHarness * h, gint p_id, gint cranks, gint pushes)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  rtmp_harness_crank_and_push_with_ts_offset (p->video_h, cranks, pushes, h->ts_offset);
}

void
rtmp_harness_request_intra (RTMPHarness * h, gint p_id)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  gst_pad_push_event (p->video_h->src_harness->sinkpad,
      gst_video_event_new_upstream_force_key_unit (
          GST_CLOCK_TIME_NONE, TRUE, 0));
}

gboolean
rtmp_harness_wait_for_rtmpsink_connection (RTMPHarness * h,
    gint p_id, gboolean connected)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  gint64 timeout = g_get_monotonic_time () + G_USEC_PER_SEC * 60;

  LOCK (p);
  while (p->rtmpsink_connected != connected) {
    WAIT_UNTIL (p, timeout);
  }
  UNLOCK (p);

  return p->rtmpsink_connected == connected;
}

gboolean
rtmp_harness_get_rtmpsink_connection (RTMPHarness * h, gint p_id)
{
  Publisher * p = g_hash_table_lookup (h->publishers, GINT_TO_POINTER (p_id));
  return p->rtmpsink_connected;
}

 /******* Subscriber ******/

static void
_rtmpsrc_connected_cb (GstElement * rtmpsrc, GParamSpec * pspec, Subscriber * s)
{
  (void)pspec;
  LOCK (s);
  g_object_get (rtmpsrc, "connected", &s->rtmpsrc_connected, NULL);
  g_debug ("******* RTMPSRC WAS %sCONNECTED *******\n",
      s->rtmpsrc_connected ? "" : "DIS");
  SIGNAL (s);
  UNLOCK (s);
}

static void
flvdemux_pad_added (GstElement * flvdemux, GstPad * srcpad, Subscriber * s)
{
  (void)flvdemux;

  gchar * padname = gst_pad_get_name (srcpad);
  if (strcmp (padname, "audio") == 0) {
    gst_harness_add_element_srcpad (s->audio_h, srcpad);
  } else if (strcmp (padname, "video") == 0) {
    gst_harness_add_element_srcpad (s->video_h, srcpad);
  }
  g_free (padname);
}

static gint
rtmp_harness_add_subscriber_full (RTMPHarness * h,
    const gchar * path, const gchar * protocol, gint port)
{
  Subscriber * s = g_new0 (Subscriber, 1);
  s->path = g_strdup (path);
  s->id = h->subscriber_count++;
  g_mutex_init (&s->lock);
  g_cond_init (&s->cond);

  gchar * pipeline = g_strdup_printf (
      "rtmpsrc blocksize=1 location=\"%s://localhost:%d/%s/%s live=1\" ! flvdemux",
      protocol, port, h->application_name, path);
  s->h = gst_harness_new_parse (pipeline);
  g_free (pipeline);

  GstElement * flvdemux = gst_harness_find_element (s->h, "flvdemux");
  g_signal_connect (flvdemux, "pad-added", G_CALLBACK (flvdemux_pad_added), s);
  /* setup harnesses ready to receive from flvdemux */
  s->audio_h = gst_harness_new_with_element (flvdemux, NULL, NULL);
  s->video_h = gst_harness_new_with_element (flvdemux, NULL, NULL);
  gst_object_unref (flvdemux);

  s->rtmpsrc = gst_harness_find_element (s->h, "rtmpsrc");
  g_signal_connect (s->rtmpsrc,
      "notify::connected", G_CALLBACK (_rtmpsrc_connected_cb), s);

  gst_harness_play (s->audio_h);
  gst_harness_play (s->video_h);
  gst_harness_play (s->h);

  g_hash_table_insert (h->subscribers, GINT_TO_POINTER (s->id), s);

  return s->id;
}

gint
rtmp_harness_add_subscriber (RTMPHarness * h, const gchar * path)
{
  return rtmp_harness_add_subscriber_full (h, path, "rtmp", h->port);
}

gint
rtmp_harness_add_subscriber_ssl (RTMPHarness * h, const gchar * path)
{
  return rtmp_harness_add_subscriber_full (h, path, "rtmps", h->ssl_port);
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
  gst_harness_teardown (s->h);

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
rtmp_harness_add_custom_audiosink (RTMPHarness * h, gint s_id, const gchar * launch_str)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  s->audio_h->sink_harness = gst_harness_new_parse (launch_str);
  gst_harness_play (s->audio_h->sink_harness);
}

static void
freq_list_cb (GstElement * sink,
    GValueArray * freq_list, Subscriber * s)
{
  (void)sink;
  if (s->freq_list)
    g_value_array_free (s->freq_list);
  s->freq_list = g_value_array_copy (freq_list);
}

void
rtmp_harness_add_audiosink (RTMPHarness * h, gint s_id, RTMPAudioCodec codec)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  if (codec == RTMP_SPEEX) {
    rtmp_harness_add_custom_audiosink (h, s_id,
        "speexdec ! pexaudioconvert ! pexcisionaudiosink");
  } else if (codec == RTMP_AAC) {
    rtmp_harness_add_custom_audiosink (h, s_id,
        "pexaacdec ! pexaudioconvert ! pexcisionaudiosink");
  } else {
    g_assert_not_reached ();
  }
  GstElement * sink = gst_harness_find_element (s->audio_h->sink_harness, "pexcisionaudiosink");
  g_signal_connect (sink,
      "freq-list", G_CALLBACK (freq_list_cb), s);
  g_object_set (sink,
      "fft-mag-threshold", -30.0,
      "fft-required-samples", 960 * 2,
      "fft-resolution", 100,
      NULL);
  gst_object_unref (sink);
}

void
rtmp_harness_add_custom_videosink (RTMPHarness * h, gint s_id, const gchar * launch_str)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  s->video_h->sink_harness = gst_harness_new_parse (launch_str);
  gst_harness_play (s->video_h->sink_harness);
}

static void
participant_list_cb (GstElement * sink,
    GValueArray * participant_list, Subscriber * s)
{
  (void)sink;
  if (s->participant_list)
    g_value_array_free (s->participant_list);
  s->participant_list = g_value_array_copy (participant_list);
}

void
rtmp_harness_add_videosink (RTMPHarness * h, gint s_id)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  rtmp_harness_add_custom_videosink (h, s_id,
      "h264parse ! "
      "capsfilter caps=\"video/x-h264, stream-format=nalu-stream\" ! "
      "pexh264dec !"
      "pexcisionvideosink");
  GstElement * sink = gst_harness_find_element (s->video_h->sink_harness, "pexcisionvideosink");
  g_signal_connect (sink,
      "participant-list", G_CALLBACK (participant_list_cb), s);
  g_object_set (sink, "participants-hint", 1, NULL);
  gst_object_unref (sink);
}

void
rtmp_harness_recv_audio (RTMPHarness * h, gint s_id, gint pushes)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  for (int i = 0; i < pushes; i++)
    g_assert (gst_harness_push_to_sink (s->audio_h));
}

void
rtmp_harness_recv_video (RTMPHarness * h, gint s_id, gint pushes)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  for (int i = 0; i < pushes; i++)
    g_assert (gst_harness_push_to_sink (s->video_h));
}

gboolean
rtmp_harness_verify_recv_audio (RTMPHarness * h, gint s_id, gint p_id)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  if (s->freq_list == NULL)
    return FALSE;
  if (s->freq_list->n_values != 1)
    return FALSE;

  gint expected_id = _get_freq_for_id (p_id);
  gint actual_id = (gint)g_value_get_uint (g_value_array_get_nth (s->freq_list, 0));
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
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
   if (s->participant_list == NULL)
    return FALSE;
  if (s->participant_list->n_values != 1)
    return FALSE;

  gint expected_id = _get_freq_for_id (p_id);
  gint actual_id = (gint)g_value_get_uint (g_value_array_get_nth (s->participant_list, 0));
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

gboolean
rtmp_harness_wait_for_rtmpsrc_connection (RTMPHarness * h,
    gint s_id, gboolean connected)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  gint64 timeout = g_get_monotonic_time () + G_USEC_PER_SEC * 60;

  LOCK (s);
  while (s->rtmpsrc_connected != connected) {
    WAIT_UNTIL (s, timeout);
  }
  UNLOCK (s);

  return s->rtmpsrc_connected == connected;
}

void
rtmp_harness_restart_rtmpsrc (RTMPHarness * h, gint s_id)
{
  Subscriber * s = g_hash_table_lookup (h->subscribers, GINT_TO_POINTER (s_id));
  gst_element_set_state (s->rtmpsrc, GST_STATE_READY);
  gst_element_set_state (s->rtmpsrc, GST_STATE_PLAYING);
}

static gboolean
rtmp_harness_on_publish (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, GObject * server)
{
  LOCK (h);
  h->notified_publishers++;
  g_debug ("got publisher (%d) on server %p for path %s params %s with client-id %d\n",
      h->notified_publishers, server, path, params, client_id);

  UNLOCK (h);

  while (h->block_on_publish)
    g_thread_yield ();

  return h->reject_publishers;
}

static void
rtmp_harness_on_publish_done (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, GObject * server)
{
  LOCK (h);
  h->notified_publishers--;
  g_debug ("lost publisher (%d) on server %p for path %s params %s with client-id %d\n",
      h->notified_publishers, server, path, params, client_id);
  UNLOCK (h);
}

static gboolean
rtmp_harness_on_play (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, GObject * server)
{
  LOCK (h);
  h->notified_subscribers++;
  g_debug ("got subscriber (%d) on server %p for path %s params %s with client-id %d\n",
      h->notified_subscribers, server, path, params, client_id);
  UNLOCK (h);

  while (h->block_on_play)
    g_thread_yield ();

  return h->reject_subscribers;
}

static void
rtmp_harness_on_play_done (RTMPHarness * h, PexRtmpClientID client_id,
    const gchar * path, const gchar * params, GObject * server)
{
  LOCK (h);
  h->notified_subscribers--;
  g_debug ("lost subscriber (%d) on server %p for path %s params %s with client-id %d\n",
      h->notified_subscribers, server, path, params, client_id);
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

gint
rtmp_harness_dialout (RTMPHarness * h_from, gint id_from,
    RTMPHarness * h_to, gint id_to, const gchar * protocol,
    const gchar * host, const gchar * ip)
{
  Subscriber * p_from = g_hash_table_lookup (h_from->publishers, GINT_TO_POINTER (id_from));
  Subscriber * s_to = g_hash_table_lookup (h_to->subscribers, GINT_TO_POINTER (id_to));
  g_assert (p_from);
  g_assert (s_to);

  gint port = h_to->port;
  if (g_strcmp0 (protocol, "rtmps") == 0)
    port = h_to->ssl_port;

  gchar * publisher_url = rtmp_harness_get_publisher_url (h_to,
    s_to->path, protocol, port, host);

  gint result = pex_rtmp_server_dialout (h_from->server, p_from->path, publisher_url, ip, 0);

  g_free (publisher_url);

  return result;
}

gint
rtmp_harness_dialin (RTMPHarness * h_from, gint id_from,
    RTMPHarness * h_to, gint id_to, const gchar * protocol,
    const gchar * host, const gchar * ip)
{
  Subscriber * s_from = g_hash_table_lookup (h_from->subscribers, GINT_TO_POINTER (id_from));
  Subscriber * p_to = g_hash_table_lookup (h_to->publishers, GINT_TO_POINTER (id_to));
  g_assert (s_from);
  g_assert (p_to);

  gint port = h_to->port;
  if (g_strcmp0 (protocol, "rtmps") == 0)
    port = h_to->ssl_port;

  gchar * publisher_url = rtmp_harness_get_publisher_url (h_to,
    p_to->path, protocol, port, host);

  gint result = pex_rtmp_server_dialin (h_from->server, s_from->path, publisher_url, ip, 0);

  g_free (publisher_url);

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
rtmp_harness_add_bad_client (RTMPHarness * h)
{
  gint fd = pex_rtmp_server_tcp_connect (h->server,
      "localhost", h->port, 0);

  /* send the first byte of the handshake, then ...nothing... */
  guint8 byte = 0x03;
  send (fd, &byte, 1, 0);
  return fd;
}

gint
rtmp_harness_add_bad_server (RTMPHarness * h, gint port)
{
  return pex_rtmp_server_add_listen_fd (h->server, port);
}

RTMPHarness *
rtmp_harness_new_full (const gchar * application_name, gint port, gint ssl_port,
    const gchar * cert, const gchar * key, const gchar * ca)
{
  gchar * certfile, * keyfile, * cafile;
  RTMPHarness * h = g_new0 (RTMPHarness, 1);
  g_mutex_init (&h->lock);
  h->application_name = g_strdup (application_name);
  h->port = port;
  h->ssl_port = ssl_port;
  h->chunk_size = 128; /* default */


  certfile = g_strdup_printf ("%s/rtmp/certs/%s", getenv("SRCDIR"), cert);
  keyfile = g_strdup_printf ("%s/rtmp/certs/%s", getenv("SRCDIR"), key);
  cafile = g_strdup_printf ("%s/rtmp/certs/%s", getenv("SRCDIR"), ca);

  h->server = pex_rtmp_server_new (application_name, h->port, h->ssl_port,
      certfile, keyfile, cafile, "/etc/ssl/certs",
      "!eNULL:!aNULL:!EXP:!DES:!RC4:!RC2:!IDEA:!ADH:ALL@STRENGTH", FALSE, FALSE);
  pex_rtmp_server_start (h->server);

  g_free (cafile);
  g_free (keyfile);
  g_free (certfile);

  h->subscribers = g_hash_table_new_full (
      NULL, NULL, NULL, (GDestroyNotify)subscriber_teardown);
  h->publishers = g_hash_table_new_full (
      NULL, NULL, NULL, (GDestroyNotify)publisher_teardown);

  g_signal_connect_swapped (h->server, "on-play",
      (GCallback)rtmp_harness_on_play, h);
  g_signal_connect_swapped (h->server, "on-play-done",
      (GCallback)rtmp_harness_on_play_done, h);
  g_signal_connect_swapped (h->server, "on-publish",
      (GCallback)rtmp_harness_on_publish, h);
  g_signal_connect_swapped (h->server, "on-publish-done",
      (GCallback)rtmp_harness_on_publish_done, h);

  return h;
}

RTMPHarness *
rtmp_harness_new_with_certs (const gchar * application_name,
    const gchar * cert, const gchar * key, const gchar * ca)
{
  RTMPHarness * h = rtmp_harness_new_full (application_name,
      STATIC_PORT, STATIC_PORT + 1, cert, key, ca);
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
      "cert_san.pem", "cert.key", "ca.pem");
}

void
rtmp_harness_teardown (RTMPHarness * h)
{
  pex_rtmp_server_stop (h->server);
  g_object_unref (h->server);

  g_hash_table_destroy (h->publishers);
  g_hash_table_destroy (h->subscribers);

  g_mutex_clear (&h->lock);

  g_free (h->application_name);
  g_free (h);
}

