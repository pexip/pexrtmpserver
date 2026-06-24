#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pextest.h"
#include <gst/check/gstcheck.h>

#include <fcntl.h>              /* open, O_RDONLY */

#if defined(_MSC_VER)
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <windows.h>
#else
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <sys/un.h>           /* sockaddr_un */
#endif

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "rtmpharness.h"

#include "rtmp.h"
#include "handshake_packet.h"
#include "wowza_connect.h"
#include "handshake.h"
#include "client.h"

#include "utils/parse.h"
#include "utils/tcp.h"
#include "utils/amf.h"

static void
rtmp_setup (void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  SSL_load_error_strings ();
  SSL_library_init ();
  OpenSSL_add_all_digests ();
#endif
}

static void
rtmp_teardown (void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  EVP_cleanup ();
#endif
}

static void
array_from_element_cb (GstElement * sink,
    GValueArray * array, GValueArray ** array_cpy)
{
  (void) sink;
  if (*array_cpy != NULL)
    g_value_array_free (*array_cpy);
  *array_cpy = g_value_array_copy (array);
}

static void
flvdemux_pad_added (GstElement * flvdemux, GstPad * srcpad, GstHarness * h)
{
  (void) flvdemux;
  gst_harness_add_element_src_pad (h, srcpad);
}

static void
flvdemux_pad_added_link (GstElement * flvdemux, GstPad * srcpad, GstHarness * h)
{
  (void) flvdemux;
  GstElement *element = GST_PAD_PARENT (GST_PAD_PEER (h->sinkpad));
  GstPad *sinkpad = gst_element_get_static_pad (element, "sink");
  gst_pad_link (srcpad, sinkpad);
  gst_object_unref (sinkpad);
  gst_object_unref (element);
}

GST_START_TEST (rtmp_speex_flv_end_to_end)
{
  SKIP_BROKEN_TEST_IF_MSVC;
  SKIP_BROKEN_TEST_IF_STATIC_BUILD;

  GstHarness *h =
      gst_harness_new_parse
      ("pexaudioconvert ! speexenc ! flvmux streamable=1 ! flvdemux");

  gst_harness_add_src (h, "pexcisionaudiosrc", TRUE);
  g_object_set (h->src_harness->element,
      "mode", 1, "freq", 900.0, "samplesperbuffer", 960, NULL);

  gst_harness_add_sink_parse (h,
      "speexdec ! pexaudioconvert ! pexcisionaudiosink");

  /* configure the sink */
  GValueArray *freq_list = NULL;
  GstElement *sink = gst_harness_find_element (h->sink_harness,
      "pexcisionaudiosink");
  g_signal_connect (sink,
      "freq-list", G_CALLBACK (array_from_element_cb), &freq_list);
  g_object_set (sink,
      "fft-mag-threshold", -25.0, "fft-required-samples", 960, NULL);
  gst_object_unref (sink);

  GstElement *flvdemux = gst_harness_find_element (h, "flvdemux");
  g_signal_connect (flvdemux, "pad-added", G_CALLBACK (flvdemux_pad_added), h);
  gst_object_unref (flvdemux);

  /* push 3 x 20ms audiobuffers */
  for (int i = 0; i < 2; i++)
    gst_harness_push_from_src (h);

  /* receive: 2x speex header-packets and 3x audio */
  for (int i = 0; i < 4; i++)
    gst_harness_push_to_sink (h);

  fail_unless_equals_int (1, freq_list->n_values);
  fail_unless_equals_int (900,
      g_value_get_uint (g_value_array_get_nth (freq_list, 0)));
  g_value_array_free (freq_list);

  gst_harness_teardown (h);
}

GST_END_TEST;

typedef struct
{
  GstClockTime send;
  GstClockTime recv;
  gint buffer_gap;
} FlvTimestampData;

static FlvTimestampData rtmp_flv_timestamping_data[] = {
  {0 * GST_SECOND, 0 * GST_SECOND, 0},
  {0 * GST_SECOND, 0 * GST_SECOND, 100},
  {0 * GST_SECOND, 2 * GST_SECOND, 0},
  //{ 2 * GST_SECOND, 0 * GST_SECOND}, /* FIXME: why is this not working? */
};

GST_START_TEST (rtmp_flv_timestamping)
{
  SKIP_BROKEN_TEST_IF_MSVC;
  SKIP_BROKEN_TEST_IF_STATIC_BUILD;

  FlvTimestampData *ts_data = &rtmp_flv_timestamping_data[__i__];
  GstClockTime send_time = ts_data->send;
  GstClockTime recv_time = ts_data->recv;
  gint buffer_gap = ts_data->buffer_gap;

  GstHarness *demux_h =
      gst_harness_new_parse ("flvdemux ! pexsync sync=0 single-segment=1");
  GstElement *flvdemux = gst_harness_find_element (demux_h, "flvdemux");
  g_signal_connect (flvdemux, "pad-added", G_CALLBACK (flvdemux_pad_added_link),
      demux_h);
  gst_object_unref (flvdemux);

  GstHarness *mux_h =
      gst_harness_new_parse
      ("pexaudioconvert ! speexenc ! flvmux streamable=1");
  gst_harness_add_src_parse (mux_h, "pexcisionaudiosrc samplesperbuffer=960",
      TRUE);
  gst_harness_use_testclock (mux_h);
  gst_harness_add_src_harness (demux_h, mux_h, TRUE);

  gst_harness_set_time (mux_h->src_harness, send_time);
  gst_harness_set_time (mux_h, send_time);
  gst_harness_set_time (demux_h, recv_time);

  fail_unless_equals_int (GST_FLOW_OK,
      gst_harness_src_crank_and_push_many (mux_h, 1, 1));
  fail_unless_equals_int (GST_FLOW_OK,
      gst_harness_src_crank_and_push_many (demux_h, 0, 5));

  /* first two meta-info buffers (without timestamp) */
  for (int i = 0; i < 2; i++) {
    GstBuffer *buf = gst_harness_pull (demux_h);
    fail_unless_equals_int64 (GST_CLOCK_TIME_NONE, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  /* followed by three buffers with the same timestamp */
  for (int i = 0; i < 3; i++) {
    GstBuffer *buf = gst_harness_pull (demux_h);
    //fail_unless_equals_int64 (recv_time, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  for (int i = 0; i < buffer_gap; i++) {
    fail_unless_equals_int (GST_FLOW_OK,
        gst_harness_src_crank_and_push_many (mux_h, 1, 1));
    gst_buffer_unref (gst_harness_pull (mux_h));
  }

  for (int i = 1 + buffer_gap; i < 10 + buffer_gap; i++) {
    fail_unless_equals_int (GST_FLOW_OK,
        gst_harness_src_crank_and_push_many (mux_h, 1, 1));
    fail_unless_equals_int (GST_FLOW_OK,
        gst_harness_src_crank_and_push_many (demux_h, 0, 1));

    GstBuffer *buf = gst_harness_pull (demux_h);
    fail_unless_equals_int64 (recv_time + i * 20 * GST_MSECOND,
        GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  gst_harness_teardown (demux_h);
}

GST_END_TEST;

GST_START_TEST (rtmp_flv_timestamping_with_valve)
{
  SKIP_BROKEN_TEST_IF_MSVC;
  SKIP_BROKEN_TEST_IF_STATIC_BUILD;

  GstHarness *demux_h =
      gst_harness_new_with_padnames ("flvdemux", "sink", NULL);
  g_signal_connect (demux_h->element, "pad-added",
      G_CALLBACK (flvdemux_pad_added), demux_h);

  GstHarness *mux_h =
      gst_harness_new_parse
      ("valve ! pexaudioconvert ! speexenc ! flvmux streamable=1");
  gst_harness_add_src_parse (mux_h, "pexcisionaudiosrc samplesperbuffer=960",
      TRUE);
  gst_harness_use_testclock (mux_h);
  gst_harness_add_src_harness (demux_h, mux_h, TRUE);

  GstElement *valve = gst_harness_find_element (mux_h, "valve");
  g_object_set (valve, "drop", TRUE, NULL);

  /* produce 10 seconds of audio, all dropped by valve */
  gst_harness_src_crank_and_push_many (mux_h, 50 * 10 + 1, 50 * 10 + 1);

  /* stop dropping */
  g_object_set (valve, "drop", FALSE, NULL);

  fail_unless_equals_int (GST_FLOW_OK,
      gst_harness_src_crank_and_push_many (mux_h, 1, 1));
  fail_unless_equals_int (GST_FLOW_OK,
      gst_harness_src_crank_and_push_many (demux_h, 0, 5));
  for (int i = 0; i < 3; i++) {
    GstBuffer *buf = gst_harness_pull (demux_h);
    fail_unless_equals_int64 (0, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  for (int i = 1; i < 10; i++) {
    fail_unless_equals_int (GST_FLOW_OK,
        gst_harness_src_crank_and_push_many (mux_h, 1, 1));
    fail_unless_equals_int (GST_FLOW_OK,
        gst_harness_src_crank_and_push_many (demux_h, 0, 1));

    GstBuffer *buf = gst_harness_pull (demux_h);
    fail_unless_equals_int64 (i * 20 * GST_MSECOND, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  gst_object_unref (valve);
  gst_harness_teardown (demux_h);
}

GST_END_TEST;

typedef struct
{
  GstHarness *audio_h;
  GstHarness *video_h;
  gboolean seen_audio_caps_event;
  gboolean seen_video_caps_event;
} FlvDemuxCapsEventData;

static GstPadProbeReturn
flvdemux_event_probe (GstPad * srcpad,
    GstPadProbeInfo * info, gpointer user_data)
{
  (void) srcpad;
  gboolean *seen_caps_event = user_data;
  GstEvent *event = GST_EVENT_CAST (info->data);
  //GST_WARNING ("Intercepted event %"GST_PTR_FORMAT, event);

  switch (GST_EVENT_TYPE (event)) {
    case GST_EVENT_CAPS:
      *seen_caps_event = TRUE;
      break;
    default:
      break;
  }
  return GST_PAD_PROBE_OK;
}

static void
flvdemux_harnesses_pad_added (GstElement * flvdemux,
    GstPad * srcpad, FlvDemuxCapsEventData * data)
{
  (void) flvdemux;
  gchar *padname = gst_pad_get_name (srcpad);
  if (strcmp (padname, "audio") == 0) {
    g_print ("Got audio\n");
    gst_harness_add_element_src_pad (data->audio_h, srcpad);
    gst_pad_add_probe (srcpad,
        GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM, flvdemux_event_probe,
        &data->seen_audio_caps_event, NULL);
  } else if (strcmp (padname, "video") == 0) {
    g_print ("Got video\n");
    gst_harness_add_element_src_pad (data->video_h, srcpad);
    gst_pad_add_probe (srcpad,
        GST_PAD_PROBE_TYPE_EVENT_DOWNSTREAM, flvdemux_event_probe,
        &data->seen_video_caps_event, NULL);
  }
  g_free (padname);
}

GST_START_TEST (flvdemux_sends_caps_events)
{
  SKIP_BROKEN_TEST_IF_MSVC;
  SKIP_BROKEN_TEST_IF_STATIC_BUILD;

  GstHarness *h =
      gst_harness_new_parse ("videotestsrc is-live=1 ! pexh264enc ! "
      "video/x-h264,stream-format=avc,alignment=au !"
      "queue ! mux.video flvmux streamable=1 name=mux ! flvdemux name=demux "
      "audiotestsrc is-live=1 samplesperbuffer=960 ! audioconvert ! speexenc ! "
      "queue ! mux.audio");

  GstElement *flvdemux = gst_harness_find_element (h, "flvdemux");

  FlvDemuxCapsEventData data;
  data.audio_h = gst_harness_new_with_element (flvdemux, NULL, NULL);
  data.video_h = gst_harness_new_with_element (flvdemux, NULL, NULL);
  data.seen_audio_caps_event = FALSE;
  data.seen_video_caps_event = FALSE;

  g_signal_connect (flvdemux, "pad-added",
      G_CALLBACK (flvdemux_harnesses_pad_added), &data);

  gst_harness_use_systemclock (h);
  gst_harness_play (h);

  for (int i = 0; i < 4; i++) {
    GstEvent *event = gst_harness_pull_event (data.audio_h);
    //GST_WARNING ("event: %"GST_PTR_FORMAT, event);
    gst_event_unref (event);
  }

  for (int i = 0; i < 4; i++) {
    GstEvent *event = gst_harness_pull_event (data.video_h);
    //GST_WARNING ("event: %"GST_PTR_FORMAT, event);
    gst_event_unref (event);
  }

  fail_unless (data.seen_audio_caps_event == TRUE);
  fail_unless (data.seen_video_caps_event == TRUE);

  gst_object_unref (flvdemux);
  gst_harness_teardown (data.audio_h);
  gst_harness_teardown (data.video_h);
  gst_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_flv_aac)
{
  GstHarness *h =
      gst_harness_new_parse
      ("pexaudioconvert ! pexaacenc ! flvmux streamable=1");
  gst_harness_add_src_parse (h, "pexcisionaudiosrc samplesperbuffer=960", TRUE);

  gst_harness_src_crank_and_push_many (h, 2, 2);

  /* first buffers are generic FLV header stuff */
  gst_buffer_unref (gst_harness_pull (h));
  gst_buffer_unref (gst_harness_pull (h));

  /* third buffer is interesting, as it contains some audio-information */
  GstBuffer *buf = gst_harness_pull (h);
  GstMapInfo map = GST_MAP_INFO_INIT;
  gst_buffer_map (buf, &map, GST_MAP_READ);

  /* 0x08 means it is audio */
  fail_unless_equals_int (0x08, map.data[0]);

  /* 0xaf means AAC, 44.1KHz, Stereo, bullshit but needed... */
  fail_unless_equals_int (0xaf, map.data[11]);

  /* 0x00 here means we have an ASC coming next... */
  fail_unless_equals_int (0x00, map.data[12]);

  /* 0x11 0x88 is the AAC Audio Specific Config (ASC), meaning AAC-LC, 48Khz, Mono */
  fail_unless_equals_int (0x11, map.data[13]);
  fail_unless_equals_int (0x88, map.data[14]);

  gst_buffer_unmap (buf, &map);
  gst_buffer_unref (buf);

  /* fourth buffer gets us some real encoded data */
  buf = gst_harness_pull (h);
  gst_buffer_map (buf, &map, GST_MAP_READ);

  /* audio + AAC bullshit byte */
  fail_unless_equals_int (0x08, map.data[0]);
  fail_unless_equals_int (0xaf, map.data[11]);

  /* but there should also be a special AAC-byte added just after the 0xaf */
  fail_unless_equals_int (0x01, map.data[12]);

  gst_buffer_unmap (buf, &map);
  gst_buffer_unref (buf);

  gst_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_audio_speex)
{
  SKIP_BROKEN_TEST_IF_MSVC;
  SKIP_BROKEN_TEST_IF_STATIC_BUILD;

  RTMPHarness *h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);

  rtmp_harness_send_audio (h, abe, 7, 7);
  rtmp_harness_recv_audio (h, bob, 6);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_audio_aac)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_audiosrc (h, abe, RTMP_AAC);
  rtmp_harness_add_audiosink (h, bob, RTMP_AAC);

  rtmp_harness_send_audio (h, abe, 20, 9);
  rtmp_harness_recv_audio (h, bob, 7);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_audio_mp3_not_supported)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_custom_audiosrc (h, abe,
      "fakesrc sync=1 sizetype=2 sizemax=160 format=3 datarate=8000 ! "
      "capsfilter caps=\"audio/mpeg,mpegversion=1,layer=3,parsed=true,rate=44100,channels=2\"");
  rtmp_harness_add_audiosink (h, bob, RTMP_AAC);

  rtmp_harness_send_audio (h, abe, 10, 10);
  //rtmp_harness_recv_audio (h, bob, 10);

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_audio_before_subscriber)
{
  RTMPAudioCodec audio_codec = (RTMPAudioCodec) __i__;
#if !HAVE_SPEEX
  if (audio_codec == RTMP_SPEEX)
    return;
#endif

  RTMPHarness *h = rtmp_harness_new ("abe_live/is/cool");
  rtmp_harness_set_chunk_size (h, 17);  /* crazy, yes, but proves we rock! */
  rtmp_harness_set_stream_id (h, 1234567);

  gint abe = rtmp_harness_add_publisher (h, "abe");

  rtmp_harness_wait_for_notified_publishers (h, 1);

  rtmp_harness_add_audiosrc (h, abe, audio_codec);
  rtmp_harness_send_audio_async (h, abe, 20, 9);

  gint bob = rtmp_harness_add_subscriber (h, "abe");

  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_audiosink (h, bob, audio_codec);
  rtmp_harness_send_audio_async (h, abe, 20, 9);

  rtmp_harness_recv_audio (h, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_video)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_videosrc (h, abe);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_video (h, abe, 3, 3);
  rtmp_harness_recv_video (h, bob, 4);

  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_audio_and_video)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_audiosrc (h, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h, abe);

  rtmp_harness_add_audiosink (h, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_audio_async (h, abe, 20, 9);
  rtmp_harness_send_video_async (h, abe, 9, 9);

  rtmp_harness_recv_audio (h, bob, 7);
  rtmp_harness_recv_video (h, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_one_publisher_n_subscribers)
{
  RTMPHarness *h_abe = rtmp_harness_new ("live");
  gint abe = rtmp_harness_add_publisher (h_abe, "abe");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  typedef struct
  {
    RTMPHarness *h_bob;
    gint bob;
  } SubCtx;

  const gint n = 10;
  SubCtx *s = g_new0 (SubCtx, n);

  for (gint i = 0; i < n; i++) {
    s[i].h_bob = rtmp_harness_new ("live");
    s[i].bob = rtmp_harness_add_subscriber (s[i].h_bob, "bob");

    rtmp_harness_add_audiosink (s[i].h_bob, s[i].bob, RTMP_AAC);
    rtmp_harness_add_videosink (s[i].h_bob, s[i].bob);

    rtmp_harness_dialin (s[i].h_bob, s[i].bob,
        h_abe, abe, "rtmp", "localhost", "127.0.0.1", 0);

    rtmp_harness_wait_for_notified_publishers (s[i].h_bob, 1);
    rtmp_harness_wait_for_notified_subscribers (h_abe, i + 1);
  }

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  for (gint i = 0; i < n; i++) {
    rtmp_harness_recv_audio (s[i].h_bob, s[i].bob, 7);
    rtmp_harness_recv_video (s[i].h_bob, s[i].bob, 9);

    rtmp_harness_verify_recv_audio (s[i].h_bob, s[i].bob, abe);
    rtmp_harness_verify_recv_video (s[i].h_bob, s[i].bob, abe);
  }

  for (gint i = 0; i < n; i++)
    rtmp_harness_teardown (s[i].h_bob);
  g_free (s);
  rtmp_harness_teardown (h_abe);
}

GST_END_TEST;

GST_START_TEST (rtmp_multiple_paths)
{
  RTMPHarness *h = rtmp_harness_new ("live");
  const gint n = 10;

  gint *abe = g_new0 (gint, n);
  gint *bob = g_new0 (gint, n);

  for (gint i = 0; i < n; i++) {
    gchar *path = g_strdup_printf ("path_%d", i);
    abe[i] = rtmp_harness_add_publisher (h, path);
    bob[i] = rtmp_harness_add_subscriber (h, path);
    rtmp_harness_wait_for_notified_publishers (h, i + 1);
    rtmp_harness_wait_for_notified_subscribers (h, i + 1);
    g_free (path);
  }

  for (gint i = 0; i < n; i++) {
    rtmp_harness_add_audiosrc (h, abe[i], RTMP_AAC);
    rtmp_harness_add_videosrc (h, abe[i]);
    rtmp_harness_add_audiosink (h, bob[i], RTMP_AAC);
    rtmp_harness_add_videosink (h, bob[i]);
  }

  for (gint i = 0; i < n; i++) {
    rtmp_harness_send_audio_async (h, abe[i], 20, 9);
    rtmp_harness_send_video_async (h, abe[i], 9, 9);
  }

  for (gint i = 0; i < n; i++) {
    rtmp_harness_recv_audio (h, bob[i], 7);
    rtmp_harness_recv_video (h, bob[i], 9);

    rtmp_harness_verify_recv_audio (h, bob[i], abe[i]);
    rtmp_harness_verify_recv_video (h, bob[i], abe[i]);
  }

  g_free (abe);
  g_free (bob);
  rtmp_harness_teardown (h);
}

GST_END_TEST;

#if !defined(_MSC_VER)
GST_START_TEST (rtmp_flash_handshake)
{
  RTMPHarness *h = rtmp_harness_new ("live");
  PexRtmpHandshake *hs = pex_rtmp_handshake_new ();

  pex_rtmp_handshake_process (hs,
      rtmp_handshake_client_packet, sizeof (rtmp_handshake_client_packet));

  guint8 *server_handshake = pex_rtmp_handshake_get_buffer (hs);
  gint length = pex_rtmp_handshake_get_length (hs);

  fail_unless_equals_int (sizeof (expected_rtmp_handshake_server_packet),
      length);
  fail_unless_equals_int (0, memcmp (server_handshake,
          expected_rtmp_handshake_server_packet, length));

  pex_rtmp_handshake_free (hs);
  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_amf3_object_parsing)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  guint8 amf3_object[] = {
    0x11,                       // AMF3
    0x0a,                       // AMF3_OBJECT
    0x0b,                       // object element count ?

    0x01,                       // start

    0x17,                       // stringlength 0x17 == 23, 23 - 1 / 2 = 11 == strlen ("hasmetadata")
    0x68, 0x61, 0x73, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,   //"hasMetadata"
    0x03,                       // AMF3_TRUE

    0x21,                       // stringlength
    0x6b, 0x65, 0x79, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c,     // "keyFrameInterval"
    0x04,                       // AMF3_INTEGER
    0x30,                       // (0x30 == 48 == keyframeinterval)

    0x19,                       // stringlength
    0x76, 0x69, 0x64, 0x65, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69, 0x64,     // "videocodecid"
    0x04,                       // AMF3_INTEGER
    0x07,                       // videocodecid == 7

    0x0b,                       // stringlength
    0x77, 0x69, 0x64, 0x74, 0x68,       // "width"
    0x04,                       // AMF3_INTEGER
    0x85, 0x00,

    0x0b,                       // stringlength
    0x6c, 0x65, 0x76, 0x65, 0x6c,       // "level"
    0x06,                       // AMF3_STRING
    0x07,                       // stringlength
    0x33, 0x2e, 0x31,           // "3.1"

    0x0b,                       // stringlength
    0x63, 0x6f, 0x64, 0x65, 0x63,       // "codec"
    0x06,                       // AMF3_STRING
    0x0f,                       // stringlength
    0x48, 0x32, 0x36, 0x34, 0x41, 0x76, 0x63,   // "H264Avc"

    0x11,                       // stringlength
    0x62, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x74, 0x68,     // "bandwith"
    0x04,                       // AMF3_INTEGER
    0x85, 0xee, 0x00,

    0x0d,                       // stringlength
    0x68, 0x65, 0x69, 0x67, 0x68, 0x74, // "height"
    0x04,                       // AMF3_INTEGER
    0x83, 0x60,

    0x0f,                       // stringlength
    0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65,   // "profile"
    0x06,                       // AMF3_STRING
    0x11,                       // stringlength
    0x62, 0x61, 0x73, 0x65, 0x6c, 0x69, 0x6e, 0x65,     // "baseline"

    0x07,                       // stringlength
    0x66, 0x70, 0x73,           // "fps"
    0x04,                       // AMF3_INTEGER
    0x1e,                       // 30

    0x01,                       // end bit?
  };

  GByteArray *buf = g_byte_array_new ();
  g_byte_array_append (buf, amf3_object, sizeof (amf3_object));
  AmfDec *dec = amf_dec_new (buf, 0);
  GstStructure *s = amf_dec_load_object (dec);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);

  gint keyFrameInterval;
  fail_unless (gst_structure_get_int (s, "keyFrameInterval",
          &keyFrameInterval));
  fail_unless_equals_int (48, keyFrameInterval);

  gint videocodecid;
  fail_unless (gst_structure_get_int (s, "videocodecid", &videocodecid));
  fail_unless_equals_int (7, videocodecid);

  gint fps;
  fail_unless (gst_structure_get_int (s, "fps", &fps));
  fail_unless_equals_int (30, fps);

  gint width;
  fail_unless (gst_structure_get_int (s, "width", &width));
  fail_unless_equals_int (640, width);

  gint height;
  fail_unless (gst_structure_get_int (s, "height", &height));
  fail_unless_equals_int (480, height);

  gint bandwith;
  fail_unless (gst_structure_get_int (s, "bandwith", &bandwith));
  fail_unless_equals_int (96000, bandwith);

  /* now try to re-encode it */
  AmfEnc *enc = amf_enc_new ();
  amf_enc_use_amf3 (enc);
  amf_enc_write_object (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (amf3_object), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, amf3_object,
          sizeof (amf3_object)));
  amf_enc_free (enc);

  gst_structure_free (s);

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_amf0_object_parsing)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  guint8 amf0_object[] = {
    0x03, 0x00, 0x06,           /* aData... */
    0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x02, 0x00,     /* Server.. */
    0x2e, 0x4e, 0x47, 0x49, 0x4e, 0x58, 0x20, 0x52,     /* .NGINX R */
    0x54, 0x4d, 0x50, 0x20, 0x28, 0x67, 0x69, 0x74,     /* TMP (git */
    0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,     /* hub.com/ */
    0x61, 0x72, 0x75, 0x74, 0x2f, 0x6e, 0x67, 0x69,     /* arut/ngi */
    0x6e, 0x78, 0x2d, 0x72, 0x74, 0x6d, 0x70, 0x2d,     /* nx-rtmp- */
    0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x29, 0x00,     /* module). */
    0x05, 0x77, 0x69, 0x64, 0x74, 0x68, 0x00, 0x40,     /* .width.@ */
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* ........ */
    0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x00,     /* .height. */
    0x40, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* @~...... */
    0x00, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61,     /* ..displa */
    0x79, 0x57, 0x69, 0x64, 0x74, 0x68, 0x00, 0x40,     /* yWidth.@ */
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* ........ */
    0x0d, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79,     /* .display */
    0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x00, 0x40,     /* Height.@ */
    0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* ~....... */
    0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,     /* .duratio */
    0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* n....... */
    0x00, 0x00, 0x00, 0x09, 0x66, 0x72, 0x61, 0x6d,     /* ....fram */
    0x65, 0x72, 0x61, 0x74, 0x65, 0x00, 0x40, 0x3e,     /* erate.@> */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,     /* ........ */
    0x66, 0x70, 0x73, 0x00, 0x40, 0x3e, 0x00, 0x00,     /* fps.@>.. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x76, 0x69,     /* ......vi */
    0x64, 0x65, 0x6f, 0x64, 0x61, 0x74, 0x61, 0x72,     /* deodatar */
    0x61, 0x74, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00,     /* ate..... */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x76, 0x69,     /* ......vi */
    0x64, 0x65, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63,     /* deocodec */
    0x69, 0x64, 0x00, 0x40, 0x1c, 0x00, 0x00, 0x00,     /* id.@.... */
    0x00, 0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x64,     /* .....aud */
    0x69, 0x6f, 0x64, 0x61, 0x74, 0x61, 0x72, 0x61,     /* iodatara */
    0x74, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* te...... */
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x61, 0x75, 0x64,     /* .....aud */
    0x69, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69,     /* iocodeci */
    0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* d....... */
    0x00, 0x00, 0x00, 0x07, 0x70, 0x72, 0x6f, 0x66,     /* ....prof */
    0x69, 0x6c, 0x65, 0x02, 0x00, 0x08, 0x62, 0x61,     /* ile.. ba */
    0x73, 0x65, 0x6c, 0x69, 0x6e, 0x65, /* seline.. */
    0x00, 0x05,                 /* ........ */
    0x6c, 0x65, 0x76, 0x65, 0x6c, 0x02, 0x00, 0x03,     /* level..  */
    0x33, 0x2e, 0x31,           /* 3.1..... */
    0x00, 0x00, 0x09
  };

  GByteArray *buf = g_byte_array_new ();
  g_byte_array_append (buf, amf0_object, sizeof (amf0_object));
  AmfDec *dec = amf_dec_new (buf, 0);
  GstStructure *s = amf_dec_load_object (dec);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);

  gdouble videocodecid;
  fail_unless (gst_structure_get_double (s, "videocodecid", &videocodecid));
  fail_unless_equals_int (7, (gint) videocodecid);

  gdouble fps;
  fail_unless (gst_structure_get_double (s, "fps", &fps));
  fail_unless_equals_int (30, (gint) fps);

  gdouble width;
  fail_unless (gst_structure_get_double (s, "width", &width));
  fail_unless_equals_int (640, (gint) width);

  gdouble height;
  fail_unless (gst_structure_get_double (s, "height", &height));
  fail_unless_equals_int (480, (gint) height);

  /* now try to re-encode it */
  AmfEnc *enc = amf_enc_new ();
  amf_enc_write_object (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (amf0_object), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, amf0_object,
          sizeof (amf0_object)));
  amf_enc_free (enc);

  gst_structure_free (s);

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_amf0_object_parsing_wowza_connect)
{
  GByteArray *buf = g_byte_array_new ();
  g_byte_array_append (buf, wowza_packet, sizeof (wowza_packet));
  AmfDec *dec = amf_dec_new (buf, 0);
  GstStructure *s = amf_dec_load_object (dec);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);

  /* now try to re-encode it */
  AmfEnc *enc = amf_enc_new ();
  amf_enc_write_object (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (wowza_packet), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, wowza_packet,
          sizeof (wowza_packet)));
  amf_enc_free (enc);

  gst_structure_free (s);
}

GST_END_TEST;

GST_START_TEST (rtmp_amf0_ecma_array_parsing)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  guint8 amf0_ecma_array[] = {
    0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74,
    0x69, 0x6f, 0x6e, 0x00,
    0x40, 0xf5, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x66, 0x69,
    0x6c, 0x65, 0x73, 0x69,
    0x7a, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x09, 0x67, 0x73, 0x74,
    0x66, 0x69, 0x6c, 0x6c, 0x65, 0x72, 0x02, 0x09, 0x25, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x00, 0x0c,
    0x61, 0x75, 0x64, 0x69, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69, 0x64,
    0x00, 0x40, 0x26, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x6d, 0x65, 0x74, 0x61, 0x64,
    0x61, 0x74, 0x61, 0x63,
    0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x02, 0x00, 0x13, 0x47, 0x53, 0x74,
    0x72, 0x65, 0x61, 0x6d,
    0x65, 0x72, 0x20, 0x46, 0x4c, 0x56, 0x20, 0x6d, 0x75, 0x78, 0x65, 0x72,
    0x00, 0x0c, 0x63, 0x72,
    0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x64, 0x61, 0x74, 0x65, 0x02, 0x00,
    0x18, 0x54, 0x68, 0x75,
    0x20, 0x53, 0x65, 0x70, 0x20, 0x32, 0x35, 0x20, 0x31, 0x38, 0x3a, 0x35,
    0x30, 0x3a, 0x31, 0x37,
    0x20, 0x32, 0x30, 0x31, 0x34, 0x00, 0x00, 0x09,
  };

  GByteArray *buf = g_byte_array_new ();
  g_byte_array_append (buf, amf0_ecma_array, sizeof (amf0_ecma_array));
  AmfDec *dec = amf_dec_new (buf, 0);
  GstStructure *s = amf_dec_load_object (dec);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);

  gdouble duration;
  fail_unless (gst_structure_get_double (s, "duration", &duration));
  fail_unless_equals_int (86400, (gint) duration);

  gdouble filesize;
  fail_unless (gst_structure_get_double (s, "filesize", &filesize));
  fail_unless_equals_int (0, (gint) filesize);

  /* now try to re-encode it */
  AmfEnc *enc = amf_enc_new ();
  amf_enc_write_ecma (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (amf0_ecma_array), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, amf0_ecma_array,
          sizeof (amf0_ecma_array)));

  amf_enc_free (enc);
  gst_structure_free (s);

  rtmp_harness_teardown (h);
}

GST_END_TEST;

static gint
_load_integer (AmfDec * dec)
{
  gint val;
  g_assert (amf_dec_load_integer (dec, &val));
  return val;
}

GST_START_TEST (rtmp_amf3_coverity_add_int)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  AmfEnc *enc = amf_enc_new ();
  amf_enc_use_amf3 (enc);
  amf_enc_add_int (enc, 5);
  amf_enc_add_int (enc, 255);
  amf_enc_add_int (enc, 16532);
  amf_enc_add_int (enc, 268435455);
  amf_enc_add_int (enc, 2147483648);
  AmfDec *dec = amf_dec_new (enc->buf, 0);

  /* and verify it is identical to the original */
  fail_unless_equals_int (_load_integer (dec), 5);
  fail_unless_equals_int (_load_integer (dec), 255);
  fail_unless_equals_int (_load_integer (dec), 16532);
  fail_unless_equals_int (_load_integer (dec), 268435455);
  fail_unless_equals_int (_load_integer (dec), 0);
  amf_enc_free (enc);
  amf_dec_free (dec);

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_amf_issue_4512)
{
  /* we need the server for GstDebugCategory */
  RTMPHarness *h = rtmp_harness_new ("live");

  guint8 rtmp_msg[] = {
    0x02, 0x00, 0x0d, 0x40, 0x73, 0x65, 0x74, 0x44,
    0x61, 0x74, 0x61, 0x46, 0x72, 0x61, 0x6d, 0x65,
    0x02, 0x00, 0x0a, 0x6f, 0x6e, 0x4d, 0x65, 0x74,
    0x61, 0x44, 0x61, 0x74, 0x61, 0x03, 0x00, 0x0c,
    0x76, 0x69, 0x64, 0x65, 0x6f, 0x63, 0x6f, 0x64,
    0x65, 0x63, 0x69, 0x64, 0x00, 0x40, 0x1c, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x63,
    0x6f, 0x64, 0x65, 0x63, 0x02, 0x00, 0x07, 0x48,
    0x32, 0x36, 0x34, 0x41, 0x76, 0x63, 0x00, 0x05,
    0x6c, 0x65, 0x76, 0x65, 0x6c, 0x02, 0x00, 0x03,
    0x33, 0x2e, 0x31, 0x00, 0x05, 0x77, 0x69, 0x64,
    0x74, 0x68, 0x00, 0x40, 0x84, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x68, 0x65, 0x69,
    0x67, 0x68, 0x74, 0x00, 0x40, 0x7e, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x62, 0x61,
    0x6e, 0x64, 0x77, 0x69, 0x64, 0x74, 0x68, 0x00,
    0x17, 0x4d, 0xae, 0x1e, 0x40, 0xef, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x66, 0x70,
    0x73, 0x00, 0x40, 0x3e, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x07, 0x70, 0x72, 0x6f, 0x66,
    0x69, 0x6c, 0x65, 0x02, 0x00, 0x08, 0x62, 0x61,
    0x73, 0x65, 0x6c, 0x69, 0x6e, 0x65, 0x00, 0x10,
    0x6b, 0x65, 0x79, 0x46, 0x72, 0x61, 0x6d, 0x65,
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c,
    0x00, 0x40, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  GByteArray *buf = g_byte_array_new ();
  g_byte_array_append (buf, rtmp_msg, sizeof (rtmp_msg));
  AmfDec *dec = amf_dec_new (buf, 0);

  gchar *type = amf_dec_load_string (dec);
  fail_unless_equals_int (0, g_strcmp0 (type, "@setDataFrame"));
  g_free (type);

  type = amf_dec_load_string (dec);
  fail_unless_equals_int (0, g_strcmp0 (type, "onMetaData"));
  g_free (type);

  GstStructure *s = amf_dec_load_object (dec);
  gst_structure_free (s);

  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);
  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_amf_unicode_issue_20402)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  guint8 rtmp_msg[] = {
    0x08, 0x00, 0x00, 0x00, 0x12, 0x00, 0x08, 0x64,
    0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x05, 0x77, 0x69, 0x64, 0x74, 0x68, 0x00,
    0x40, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74,
    0x00, 0x40, 0x86, 0x80, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0d, 0x76, 0x69, 0x64, 0x65, 0x6f,
    0x64, 0x61, 0x74, 0x61, 0x72, 0x61, 0x74, 0x65,
    0x00, 0x40, 0xbb, 0x5b, 0xf4, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x09, 0x66, 0x72, 0x61, 0x6d, 0x65,
    0x72, 0x61, 0x74, 0x65, 0x00, 0x40, 0x3e, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x76,
    0x69, 0x64, 0x65, 0x6f, 0x63, 0x6f, 0x64, 0x65,
    0x63, 0x69, 0x64, 0x00, 0x40, 0x1c, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x61, 0x75,
    0x64, 0x69, 0x6f, 0x64, 0x61, 0x74, 0x61, 0x72,
    0x61, 0x74, 0x65, 0x00, 0x40, 0x6b, 0xf5, 0x60,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x75,
    0x64, 0x69, 0x6f, 0x73, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x72, 0x61, 0x74, 0x65, 0x00, 0x40, 0xe5,
    0x88, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
    0x61, 0x75, 0x64, 0x69, 0x6f, 0x73, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x73, 0x69, 0x7a, 0x65, 0x00,
    0x40, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x06, 0x73, 0x74, 0x65, 0x72, 0x65, 0x6f,
    0x01, 0x01, 0x00, 0x0c, 0x61, 0x75, 0x64, 0x69,
    0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69, 0x64,
    0x00, 0x40, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0b, 0x6d, 0x61, 0x6a, 0x6f, 0x72,
    0x5f, 0x62, 0x72, 0x61, 0x6e, 0x64, 0x02, 0x00,
    0x04, 0x71, 0x74, 0x20, 0x20, 0x00, 0x0d, 0x6d,
    0x69, 0x6e, 0x6f, 0x72, 0x5f, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x02, 0x00, 0x01, 0x30,
    0x00, 0x11, 0x63, 0x6f, 0x6d, 0x70, 0x61, 0x74,
    0x69, 0x62, 0x6c, 0x65, 0x5f, 0x62, 0x72, 0x61,
    0x6e, 0x64, 0x73, 0x02, 0x00, 0x04, 0x71, 0x74,
    0x20, 0x20, 0x00, 0x1e, 0x63, 0x6f, 0x6d, 0x2e,
    0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x71, 0x75,
    0x69, 0x63, 0x6b, 0x74, 0x69, 0x6d, 0x65, 0x2e,
    0x69, 0x73, 0x2d, 0x6d, 0x6f, 0x6e, 0x74, 0x61,
    0x67, 0x65, 0x02, 0x00, 0x06, 0x69, 0x4d, 0x6f,
    0x76, 0x69, 0x65, 0x00, 0x1b, 0x63, 0x6f, 0x6d,
    0x2e, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2e, 0x71,
    0x75, 0x69, 0x63, 0x6b, 0x74, 0x69, 0x6d, 0x65,
    0x2e, 0x61, 0x72, 0x74, 0x77, 0x6f, 0x72, 0x6b,
    0x02, 0x00, 0x04, 0xff, 0xd8, 0xff, 0xe0, 0x00,
    0x07, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x72,
    0x02, 0x00, 0x0d, 0x4c, 0x61, 0x76, 0x66, 0x35,
    0x37, 0x2e, 0x38, 0x33, 0x2e, 0x31, 0x30, 0x30,
    0x00, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x69,
    0x7a, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
  };

  GByteArray *buf = g_byte_array_new ();
  g_byte_array_append (buf, rtmp_msg, sizeof (rtmp_msg));
  AmfDec *dec = amf_dec_new (buf, 0);
  GstStructure *s = amf_dec_load_object (dec);
  gchar *s_str = gst_structure_to_string (s);
  GST_INFO ("%s", s_str);
  g_free (s_str);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);
  gst_structure_free (s);
  rtmp_harness_teardown (h);
}

GST_END_TEST;

static GByteArray *
generate_random_data (GRand * rand)
{
  GByteArray *buf = g_byte_array_new ();
  guint length = g_rand_int_range (rand, 0, 128);
  buf = g_byte_array_set_size (buf, length);

  for (guint i = 0; i < length; i++)
    buf->data[i] = g_rand_int_range (rand, 0, G_MAXUINT8);

  return buf;
}

GST_START_TEST (rtmp_amf_dec_fuzzing)
{
  /* we need the server for GstDebugCategory */
  RTMPHarness *h = rtmp_harness_new ("live");
  GRand *rand = g_rand_new_with_seed (42);

  for (gint i = 0; i < 100 /*000000 */ ; i++) {
    GByteArray *buf = generate_random_data (rand);
    AmfDec *dec = amf_dec_new (buf, 0);

    gst_structure_free (amf_dec_load_object (dec));
    g_free (amf_dec_load_string (dec));
    g_free (amf_dec_load_key (dec));

    gdouble d_ret;
    gint i_ret;
    gboolean b_ret;
    amf_dec_load_number (dec, &d_ret);
    amf_dec_load_integer (dec, &i_ret);
    amf_dec_load_boolean (dec, &b_ret);

    amf_dec_free (dec);
    g_byte_array_free (buf, TRUE);
  }

  g_rand_free (rand);
  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_amf_null_object)
{
  RTMPHarness *h = rtmp_harness_new ("live");
  AmfEnc *enc;

  /* AMF0 */
  enc = amf_enc_new ();
  amf_enc_write_object (enc, NULL);
  amf_enc_free (enc);

  /* AMF3 */
  enc = amf_enc_new ();
  amf_enc_use_amf3 (enc);
  amf_enc_write_object (enc, NULL);
  amf_enc_free (enc);

  /* ECMA */
  enc = amf_enc_new ();
  amf_enc_use_amf3 (enc);
  amf_enc_write_ecma (enc, NULL);
  amf_enc_free (enc);

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_window_size)
{
  PexRtmpServer *server = pex_rtmp_server_new ("pexip", 1935,
      0, NULL, NULL, NULL, NULL, NULL, FALSE, FALSE);
  pex_rtmp_server_start (server);
  Connections *connections = connections_new ();
  Client *client =
      client_new ((GObject *) server, 0, connections, 1337, 128, NULL);
  gint32 window_size = htonl (100);
  guint8 window_size_buf[4];
  memcpy (&window_size_buf[0], &window_size, sizeof (window_size));
  GByteArray *buf = g_byte_array_new ();
  g_byte_array_append (buf, window_size_buf, sizeof (window_size_buf));
  RTMPMessage message = {
    .fmt = 0,
    .type = MSG_WINDOW_ACK_SIZE,
    .len = 4,
    .timestamp = 0,
    .abs_timestamp = 0,
    .msg_stream_id = 0,
    .buf = buf
  };

  client_handle_message (client, &message);
  fail_unless_equals_int (client->window_size, 100);
  fail_unless (!client_window_size_reached (client));
  client->bytes_received_since_ack = 100;
  fail_unless (client_window_size_reached (client));
  g_byte_array_free (buf, TRUE);
  connections_free (connections);
  client_unref (client);
  pex_rtmp_server_stop (server);
  pex_rtmp_server_free (server);
}

GST_END_TEST;

#endif /* _MSC_VER */

GST_START_TEST (rtmp_server_get_port_dynamic)
{
  /* port=0 asks the kernel to pick a free port; ssl_port=-1 means "don't listen on SSL" */
  PexRtmpServer *server = pex_rtmp_server_new ("pexip",
      0, -1, NULL, NULL, NULL, NULL, NULL, FALSE, FALSE);
  fail_unless (pex_rtmp_server_start (server));

  /* the kernel should have assigned a real, non-zero port */
  gint port = pex_rtmp_server_get_port (server);
  fail_if (port == INVALID_PORT);
  fail_if (port == 0);
  fail_unless (port > 0 && port <= G_MAXUINT16);

  /* SSL was disabled (-1), so we should get INVALID_PORT back */
  fail_unless_equals_int (INVALID_PORT, pex_rtmp_server_get_ssl_port (server));

  pex_rtmp_server_stop (server);
  pex_rtmp_server_free (server);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_get_ssl_port_dynamic)
{
  /* mirror of the above, but for the SSL listener */
  PexRtmpServer *server = pex_rtmp_server_new ("pexip",
      -1, 0, NULL, NULL, NULL, NULL, NULL, FALSE, FALSE);
  fail_unless (pex_rtmp_server_start (server));

  gint ssl_port = pex_rtmp_server_get_ssl_port (server);
  fail_if (ssl_port == INVALID_PORT);
  fail_if (ssl_port == 0);
  fail_unless (ssl_port > 0 && ssl_port <= G_MAXUINT16);

  fail_unless_equals_int (INVALID_PORT, pex_rtmp_server_get_port (server));

  pex_rtmp_server_stop (server);
  pex_rtmp_server_free (server);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_get_port_dynamic_both)
{
  /* both listeners on dynamic ports - they must end up different */
  PexRtmpServer *server = pex_rtmp_server_new ("pexip",
      0, 0, NULL, NULL, NULL, NULL, NULL, FALSE, FALSE);
  fail_unless (pex_rtmp_server_start (server));

  gint port = pex_rtmp_server_get_port (server);
  gint ssl_port = pex_rtmp_server_get_ssl_port (server);

  fail_if (port == INVALID_PORT);
  fail_if (ssl_port == INVALID_PORT);
  fail_if (port == ssl_port);

  pex_rtmp_server_stop (server);
  pex_rtmp_server_free (server);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_get_port_unset)
{
  /* -1 means "no listener" for both - getters should report INVALID_PORT */
  PexRtmpServer *server = pex_rtmp_server_new ("pexip",
      -1, -1, NULL, NULL, NULL, NULL, NULL, FALSE, FALSE);
  fail_unless (pex_rtmp_server_start (server));

  fail_unless_equals_int (INVALID_PORT, pex_rtmp_server_get_port (server));
  fail_unless_equals_int (INVALID_PORT, pex_rtmp_server_get_ssl_port (server));

  pex_rtmp_server_stop (server);
  pex_rtmp_server_free (server);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_get_port_before_start)
{
  /* before start() there is no bound socket, so the getters must not crash
   * and must return INVALID_PORT */
  PexRtmpServer *server = pex_rtmp_server_new ("pexip",
      0, 0, NULL, NULL, NULL, NULL, NULL, FALSE, FALSE);

  fail_unless_equals_int (INVALID_PORT, pex_rtmp_server_get_port (server));
  fail_unless_equals_int (INVALID_PORT, pex_rtmp_server_get_ssl_port (server));

  pex_rtmp_server_free (server);
}

GST_END_TEST;

typedef struct
{
  const gchar *url;
  gboolean parsed;
  const gchar *protocol;
  gint port;
  const gchar *ip;
  const gchar *app_name;
  const gchar *path;
  const gchar *username;
  const gchar *password;
} RtmpParseData;

static RtmpParseData rtmp_parse_data[] = {
  /* ipv4 */
  {
        "rtmp://10.47.4.114:666/this/actually/works live=1", TRUE,
        "rtmp", 666, "10.47.4.114", "this/actually", "works", NULL, NULL,
      },

  /* ipv4, no port, should default to 1935 */
  {
        "rtmp://10.47.4.114/this/actually/works live=1", TRUE,
        "rtmp", 1935, "10.47.4.114", "this/actually", "works", NULL, NULL,
      },

  /* ipv6 */
  {
        "rtmp://[2001:db8:0:1]:456/this/actually/works live=1", TRUE,
        "rtmp", 456, "2001:db8:0:1", "this/actually", "works", NULL, NULL,
      },

  /* ipv6, no ports, should default to 1935 */
  {
        "rtmp://FE80:0000:0000:0000:0202:B3FF:FE1E:8329/this/actually/works",
        TRUE,
        "rtmp", 1935, "FE80:0000:0000:0000:0202:B3FF:FE1E:8329",
        "this/actually", "works", NULL, NULL,
      },

  /* rtmpx - should fail */
  {
        "rtmpx://10.47.4.114:666/this/actually/works", FALSE,
        NULL, 0, NULL, NULL, NULL, NULL, NULL,
      },

  /* no path - should fail */
  {
        "rtmp://10.47.4.114:666/this", FALSE,
        NULL, 0, NULL, NULL, NULL, NULL, NULL,
      },

  /* bogus, should fail */
  {
        "This is bullshit!", FALSE,
        NULL, 0, NULL, NULL, NULL, NULL, NULL,
      },

  /* missing "/" - should fail */
  {
        "rtmp:/10.47.4.114:666/this/actually/works", FALSE,
        NULL, 0, NULL, NULL, NULL, NULL, NULL,
      },

  /* missing port - should fail */
  {
        "rtmp://10.47.4.114:/this/actually/works", FALSE,
        NULL, 0, NULL, NULL, NULL, NULL, NULL,
      },

  /* username & password */
  {
        "rtmp://username:password@10.47.4.114:666/app/path", TRUE,
        "rtmp", 666, "10.47.4.114", "app", "path", "username", "password",
      },

  /* password is empty string */
  {
        "rtmp://username:@10.47.4.114:666/app/path", TRUE,
        "rtmp", 666, "10.47.4.114", "app", "path", "username", "",
      },

  /* username is empty string */
  {
        "rtmp://:password@10.47.4.114:666/app/path", TRUE,
        "rtmp", 666, "10.47.4.114", "app", "path", "", "password",
      },

  /* @ without : */
  {
        "rtmp://usernamepassword@10.47.4.114:666/app/path", FALSE,
        NULL, 0, NULL, NULL, NULL, NULL, NULL,
      },

  /* Akamai */
  {
        "rtmp://USERNAME:PASSWORD@p.ep627802.i.akamaientrypoint.net/EntryPoint/pexiptest_01_1200@627802",
        TRUE,
        "rtmp", 1935, "p.ep627802.i.akamaientrypoint.net", "EntryPoint",
        "pexiptest_01_1200@627802", "USERNAME", "PASSWORD",
      },

  /* Isses 15324 */
  {
        "rtmp://stream11.abiliteam.com/ability218push/mp4:0xdf1ba697c16e29274f6875473fca919b_-1471283940_cam1?alias=jens@pexip.com&eventname=Meeting%20DH%202",
        TRUE, "rtmp", 1935, "stream11.abiliteam.com", "ability218push",
        "mp4:0xdf1ba697c16e29274f6875473fca919b_-1471283940_cam1?alias=jens@pexip.com&eventname=Meeting%20DH%202",
        NULL, NULL,
      },

};

GST_START_TEST (rtmp_server_url_parse)
{
  RTMPHarness *h = rtmp_harness_new ("dummy");
  RtmpParseData *d = &rtmp_parse_data[__i__];

  gchar *protocol = NULL;
  gint port;
  gchar *ip = NULL;
  gchar *app_name = NULL;
  gchar *path = NULL;
  gchar *username = NULL;
  gchar *password = NULL;

  gboolean parsed = parse_rtmp_url (d->url,
      &protocol, &port, &ip, &app_name, &path, &username, &password);

  fail_unless (parsed == d->parsed);
  if (d->parsed) {
    fail_unless_equals_string (protocol, d->protocol);
    fail_unless_equals_int (port, d->port);
    fail_unless_equals_string (ip, d->ip);
    fail_unless_equals_string (app_name, d->app_name);
    fail_unless_equals_string (path, d->path);
    fail_unless_equals_string (username, d->username);
    fail_unless_equals_string (password, d->password);
  }

  g_free (protocol);
  g_free (ip);
  g_free (app_name);
  g_free (path);
  g_free (username);
  g_free (password);
  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialin)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 128);
  rtmp_harness_set_chunk_size (h_bob, 128);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialin (h_bob, bob, h_abe, abe, "rtmp", "localhost", "127.0.0.1",
      0);
  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_wait_for_notified_publishers (h_bob, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialin_and_dialout_speex)
{
  SKIP_BROKEN_TEST_IF_MSVC;
  SKIP_BROKEN_TEST_IF_STATIC_BUILD;

  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 1);
  rtmp_harness_set_chunk_size (h_bob, 1);

  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  /* doing dialout */
  gint abe_publisher = rtmp_harness_add_publisher (h_abe, "abe_publisher");
  gint bob_subscriber = rtmp_harness_add_subscriber (h_bob, "bob_subscriber");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  /* doing dialin */
  gint bob_publisher = rtmp_harness_add_publisher (h_bob, "bob_publisher");
  gint abe_subscriber = rtmp_harness_add_subscriber (h_abe, "abe_subscriber");

  rtmp_harness_wait_for_notified_publishers (h_bob, 1);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_add_audiosrc (h_abe, abe_publisher, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe_publisher);

  rtmp_harness_add_audiosink (h_bob, bob_subscriber, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob_subscriber);

  rtmp_harness_add_audiosrc (h_bob, bob_publisher, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_bob, bob_publisher);

  rtmp_harness_add_audiosink (h_abe, abe_subscriber, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_abe, abe_subscriber);

  rtmp_harness_dialout (h_abe, abe_publisher, h_bob, bob_subscriber,
      "rtmp", "localhost", "127.0.0.1", 0);
  /* with dialout, from abe to bob, abe adds a subscriber and
     bob adds a publisher */
  rtmp_harness_wait_for_notified_subscribers (h_abe, 2);
  rtmp_harness_wait_for_notified_publishers (h_bob, 2);


  rtmp_harness_dialin (h_abe, abe_subscriber, h_bob, bob_publisher,
      "rtmp", "localhost", "127.0.0.1", 0);
  /* with dialin, from abe to bob, abe adds a publisher and
     bob adds a subscriber */
  rtmp_harness_wait_for_notified_publishers (h_abe, 2);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 2);

  rtmp_harness_send_audio_async (h_abe, abe_publisher, 3, 5);
  rtmp_harness_send_video_async (h_abe, abe_publisher, 3, 3);

  rtmp_harness_recv_audio (h_bob, bob_subscriber, 4);
  rtmp_harness_recv_video (h_bob, bob_subscriber, 4);

  rtmp_harness_send_audio_async (h_bob, bob_publisher, 3, 5);
  rtmp_harness_send_video_async (h_bob, bob_publisher, 3, 3);

  rtmp_harness_recv_audio (h_abe, abe_subscriber, 4);
  rtmp_harness_recv_video (h_abe, abe_subscriber, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob_subscriber,
          abe_publisher));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob_subscriber,
          abe_publisher));
  fail_unless (rtmp_harness_verify_recv_audio (h_abe, abe_subscriber,
          bob_publisher));
  fail_unless (rtmp_harness_verify_recv_video (h_abe, abe_subscriber,
          bob_publisher));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialin_and_dialout_aac)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 1);
  rtmp_harness_set_chunk_size (h_bob, 1);

  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  /* doing dialout */
  gint abe_publisher = rtmp_harness_add_publisher (h_abe, "abe_publisher");
  gint bob_subscriber = rtmp_harness_add_subscriber (h_bob, "bob_subscriber");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  /* doing dialin */
  gint bob_publisher = rtmp_harness_add_publisher (h_bob, "bob_publisher");
  gint abe_subscriber = rtmp_harness_add_subscriber (h_abe, "abe_subscriber");

  rtmp_harness_wait_for_notified_publishers (h_bob, 1);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_add_audiosrc (h_abe, abe_publisher, RTMP_AAC);
  rtmp_harness_add_audiosink (h_bob, bob_subscriber, RTMP_AAC);

  rtmp_harness_add_audiosrc (h_bob, bob_publisher, RTMP_AAC);
  rtmp_harness_add_audiosink (h_abe, abe_subscriber, RTMP_AAC);

  rtmp_harness_dialout (h_abe, abe_publisher, h_bob, bob_subscriber,
      "rtmp", "localhost", "127.0.0.1", 0);
  /* with dialout, from abe to bob, abe adds a subscriber and
     bob adds a publisher */
  rtmp_harness_wait_for_notified_subscribers (h_abe, 2);
  rtmp_harness_wait_for_notified_publishers (h_bob, 2);


  rtmp_harness_dialin (h_abe, abe_subscriber, h_bob, bob_publisher,
      "rtmp", "localhost", "127.0.0.1", 0);
  /* with dialin, from abe to bob, abe adds a publisher and
     bob adds a subscriber */
  rtmp_harness_wait_for_notified_publishers (h_abe, 2);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 2);

  rtmp_harness_send_audio (h_abe, abe_publisher, 20, 9);
  rtmp_harness_recv_audio (h_bob, bob_subscriber, 7);
  rtmp_harness_send_audio (h_bob, bob_publisher, 20, 9);
  rtmp_harness_recv_audio (h_abe, abe_subscriber, 7);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob_subscriber,
          abe_publisher));
  fail_unless (rtmp_harness_verify_recv_audio (h_abe, abe_subscriber,
          bob_publisher));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_wait_for_notified_publishers (h_bob, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_adobe_auth_success)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");

  rtmp_harness_set_server_auth (h_bob, "username", "password");
  rtmp_harness_set_dialout_auth (h_bob, "username", "password");

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_wait_for_notified_publishers (h_bob, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_adobe_auth_with_srcport)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");

  rtmp_harness_set_server_auth (h_bob, "username", "password");
  rtmp_harness_set_dialout_auth (h_bob, "username", "password");

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 40016);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_wait_for_notified_publishers (h_bob, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_adobe_auth_fail_wrong_credentials)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");

  rtmp_harness_set_server_auth (h_bob, "username", "password");
  rtmp_harness_set_dialout_auth (h_bob, "not", "correct");

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 0);

  /* check we are unable to connect */
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);
  //rtmp_harness_wait_for_notified_subscribers (h_bob, -1);

  /* abe got told it needed auth, and bob told abe it rejected him based on auth */
  fail_unless_equals_int (h_abe->play_done_reason,
      PEX_RTMP_SERVER_STATUS_NEED_AUTH);
  fail_unless_equals_int (h_bob->play_done_reason,
      PEX_RTMP_SERVER_STATUS_AUTH_REJECTED);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_adobe_auth_fail_no_credentials)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");

  rtmp_harness_set_server_auth (h_bob, "username", "password");

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 40016);

  /* check we are unable to connect */
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 0);

  /* abe got told it needed auth, and bob told abe it rejected him based on auth */
  fail_unless_equals_int (h_abe->play_done_reason,
      PEX_RTMP_SERVER_STATUS_NEED_AUTH);
  fail_unless_equals_int (h_bob->play_done_reason,
      PEX_RTMP_SERVER_STATUS_AUTH_REJECTED);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_and_dialin_issue_14907)
{
  RTMPHarness *h_trans = rtmp_harness_new ("app/trans");
  RTMPHarness *h_proxy = rtmp_harness_new ("app/proxy");
  RTMPHarness *h_youtube = rtmp_harness_new ("app/youtube");

  rtmp_harness_set_chunk_size (h_trans, 1);
  rtmp_harness_set_chunk_size (h_proxy, 1);
  rtmp_harness_set_chunk_size (h_youtube, 1);

  rtmp_harness_set_stream_id (h_trans, 11111);
  rtmp_harness_set_stream_id (h_proxy, 22222);
  rtmp_harness_set_stream_id (h_youtube, 33333);

  /* media origin */
  gint trans_pub = rtmp_harness_add_publisher (h_trans, "trans_stream");
  rtmp_harness_add_audiosrc (h_trans, trans_pub, RTMP_AAC);

  /* media destination */
  gint youtube_sub = rtmp_harness_add_subscriber (h_youtube, "youtube_stream");
  rtmp_harness_add_audiosink (h_youtube, youtube_sub, RTMP_AAC);

  /* we initate two connections from the proxy-node. We dial-out to youtube,
     to send them media, and we dial-in from the transcoding-node, to have
     them send us media, so the path will be:
     testharness -> [trans] -> [proxy] -> [youtube] -> testharness
   */

  /* first dial-out to youtube, creating an
     internal subscriber to "proxy_stream" on the proxy-node, and then
     publishing that to the "youtube_stream" on the youtube-node
   */
  gchar *dialout_path_proxy_to_youtube = rtmp_harness_create_url (h_youtube,
      "youtube_stream", "rtmp", h_youtube->port, "localhost");
  pex_rtmp_server_dialout (h_proxy->server,
      "proxy_stream", dialout_path_proxy_to_youtube, "127.0.0.1", 0);
  g_free (dialout_path_proxy_to_youtube);

  /* then we dial-in to trans, creating a subscriber to "trans_stream" on the
     trans-node, and having that publish to the "proxy_stream" on the proxy-node
   */
  gchar *dialin_path_proxy_from_trans = rtmp_harness_create_url (h_trans,
      "trans_stream", "rtmp", h_trans->port, "localhost");
  pex_rtmp_server_dialin (h_proxy->server,
      "proxy_stream", dialin_path_proxy_from_trans, "127.0.0.1", 0);
  g_free (dialin_path_proxy_from_trans);

  /* when all is up, we should have one publisher and one subscriber on
     each node, except for the inital publisher to the trans-node, that will
     appear only after we start sending media
   */
  rtmp_harness_wait_for_notified_subscribers (h_trans, 1);
  rtmp_harness_wait_for_notified_publishers (h_proxy, 1);
  rtmp_harness_wait_for_notified_subscribers (h_proxy, 1);
  rtmp_harness_wait_for_notified_publishers (h_youtube, 1);

  rtmp_harness_send_audio (h_trans, trans_pub, 20, 9);
  rtmp_harness_recv_audio (h_youtube, youtube_sub, 7);

  fail_unless (rtmp_harness_verify_recv_audio (h_youtube, youtube_sub,
          trans_pub));

  /* now disconnect the publisher, and verify that this propegates all the
     way to the youtube node */
  rtmp_harness_remove_publisher (h_trans, trans_pub);

  rtmp_harness_wait_for_notified_publishers (h_trans, 0);
  rtmp_harness_wait_for_notified_subscribers (h_trans, 0);
  rtmp_harness_wait_for_notified_publishers (h_proxy, 0);
  rtmp_harness_wait_for_notified_subscribers (h_proxy, 0);
  rtmp_harness_wait_for_notified_publishers (h_youtube, 0);
  rtmp_harness_wait_for_notified_subscribers (h_youtube, 0);

  rtmp_harness_teardown (h_trans);
  rtmp_harness_teardown (h_proxy);
  rtmp_harness_teardown (h_youtube);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ip_list)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "unreachable",
      "bougus,wrong,crazy,almost,127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_tcp_disconnect_tcp)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_wait_for_notified_publishers (h_bob, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_remove_publisher (h_abe, abe);

  rtmp_harness_wait_for_notified_subscribers (h_abe, 0);
  rtmp_harness_wait_for_notified_publishers (h_bob, 0);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;


GST_START_TEST (rtmp_server_dialout_ipv6)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "::1", "::1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_dead_host_bug_4130)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);
  rtmp_harness_set_tcp_syncnt (h_abe, 1);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "10.255.255.254",
      "10.255.255.254", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ssl_cn_dns)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_cn_dns.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ssl_san_dns)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_san.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ssl_cn_ip)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_cn_ip.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ssl_san_ip)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_san.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ssl_san_mismatch)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_san_mismatch.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);
  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, -2);

  fail_unless_equals_int (h_abe->play_done_reason,
      PEX_RTMP_SERVER_STATUS_SSL_ACCEPT_FAILED);
  fail_unless_equals_int (h_bob->play_done_reason,
      PEX_RTMP_SERVER_STATUS_SSL_ACCEPT_FAILED);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ssl_no_trust)
{
  RTMPHarness *h_abe = rtmp_harness_new_with_certs ("abe_live/is/cool",
      "cert_san.pem", "cert.key", "ca-missing.pem");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);
  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, -2);

  fail_unless_equals_int (h_abe->play_done_reason,
      PEX_RTMP_SERVER_STATUS_SSL_ACCEPT_FAILED);
  fail_unless_equals_int (h_bob->play_done_reason,
      PEX_RTMP_SERVER_STATUS_SSL_ACCEPT_FAILED);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ecdh)
{
  RTMPHarness *h_abe = rtmp_harness_new_with_ciphers ("abe_live/is/cool",
      "!aNULL:!eNULL:ECDHE");
  RTMPHarness *h_bob = rtmp_harness_new_with_ciphers ("bob_live/is/also",
      "!aNULL:!eNULL:ECDHE");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_extended_timestamp)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_wait_for_notified_publishers (h_bob, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  /* jump time to the point where extended timestamps starts */
  rtmp_harness_set_timestamp_offset (h_abe, 0xffffff * GST_MSECOND);

  /* get an intra frame */
  rtmp_harness_request_intra (h_abe, abe);

  /* verify we can still send and receive just fine */
  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);
  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);
  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_nonblocking_handshake)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint fd = rtmp_harness_add_bad_client (h);

  rtmp_harness_teardown (h);
  tcp_disconnect (fd);
}

GST_END_TEST;

GST_START_TEST (rtmps_nonblocking_handshake)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint fd = rtmp_harness_add_bad_client_ssl (h);

  g_usleep (G_USEC_PER_SEC);

  gint poll_count = rtmp_harness_get_poll_count (h);
  /* We don't know precisely how many times poll() will
   * be called but we expect it to be relatively small.
   */
  g_assert_cmpint (poll_count, <, 20);

  rtmp_harness_teardown (h);
  tcp_disconnect (fd);
}

GST_END_TEST;

GST_START_TEST (rtmp_nonblocking_outgoing_handshake)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint fd = rtmp_harness_add_bad_server (h, 2000);

  pex_rtmp_server_dialout (h->server, "streamname0",
      "rtmp://localhost:2000/app/streamname1", "127.0.0.1", 0);

  rtmp_harness_teardown (h);
  tcp_disconnect (fd);
}

GST_END_TEST;

GST_START_TEST (rtmp_connect_can_be_cancelled)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  pex_rtmp_server_dialout (h->server, "streamname0",
      "rtmp://youtube.com/live/akjasdnaskjd", "youtube.com", 0);

  gint64 now = g_get_monotonic_time ();

  rtmp_harness_teardown (h);

  gint64 then = g_get_monotonic_time ();

  fail_unless (then - now < G_USEC_PER_SEC * 10);
}

GST_END_TEST;

GST_START_TEST (rtmp_nonblocking_connect)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");
  rtmp_harness_wait_for_notified_publishers (h_abe, 1);
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);
  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_wait_for_notified_publishers (h_bob, 1);

  /* do two bogus dialouts to see if the connect() call
     will block us from sending audio data */
  pex_rtmp_server_dialout (h_abe->server, "streamname0",
      "rtmp://youtube.com/live/akjasdnaskjd", "youtube.com", 0);
  pex_rtmp_server_dialout (h_bob->server, "streamname0",
      "rtmp://youtube.com/live/akjasdnaskjd", "youtube.com", 0);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_recv_audio (h_bob, bob, 9);
  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_stress_bug_4648)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  g_object_set (h_abe->server, "ignore-localhost", TRUE, NULL);
  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);

  const gint harnesses = 10;
  RTMPHarness **h_bob = g_newa (RTMPHarness *, harnesses);

  for (gint i = 0; i < harnesses; i++) {

    h_bob[i] =
        rtmp_harness_new_with_ports ("bob_live/is/also", 20000 + i, 30001 + i);
    g_object_set (h_bob[i]->server, "ignore-localhost", TRUE, NULL);
    gchar *path = g_strdup_printf ("bob_%d", i);
    gint bob = rtmp_harness_add_subscriber (h_bob[i], path);
    g_free (path);

    rtmp_harness_lock (h_abe);
    rtmp_harness_dialout (h_abe, abe, h_bob[i], bob, "rtmp", "127.0.0.1",
        "127.0.0.1", 0);
    rtmp_harness_unlock (h_abe);
    rtmp_harness_send_audio (h_abe, abe, 20, 9);
  }

  rtmp_harness_teardown (h_abe);

  for (gint i = 0; i < harnesses; i++) {
    rtmp_harness_teardown (h_bob[i]);
  }

}

GST_END_TEST;

GST_START_TEST (rtmp_server_ignore_localhost)
{
  RTMPHarness *h = rtmp_harness_new ("live");
  g_object_set (h->server, "ignore-localhost", TRUE, NULL);

  /* we normally would wait for notified to get around the problem
     that a publisher being active before a subscriber is ready,
     will cause packets to be dropped, but in this case there
     are no nofification, so we just add the subscriber first! */
  gint bob = rtmp_harness_add_subscriber (h, "test");
  gint abe = rtmp_harness_add_publisher (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_AAC);
  rtmp_harness_add_audiosink (h, bob, RTMP_AAC);

  rtmp_harness_send_audio (h, abe, 20, 9);
  rtmp_harness_recv_audio (h, bob, 7);

  fail_unless_equals_int (0, h->notified_subscribers);
  fail_unless_equals_int (0, h->notified_publishers);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_stress_bug_5467)
{
  RTMPHarness *h_abe;
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");

  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");
  gint abe;

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  for (int i = 0; i < 20; i++) {
    printf ("Added publisher %d\n", i);
    h_abe = rtmp_harness_new ("abe_live/is/cool");
    rtmp_harness_set_stream_id (h_abe, 1234567);
    abe = rtmp_harness_add_publisher (h_abe, "abe");
    rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
    rtmp_harness_add_videosrc (h_abe, abe);

    rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
        "127.0.0.1", 0);
    /* rtmp_harness_wait_for_notified_subscribers (h_abe, 1); */

    /* rtmp_harness_send_audio_async (h_abe, abe, 6, 8); */
    /* rtmp_harness_send_video_async (h_abe, abe, 5, 5); */

    /* rtmp_harness_recv_audio (h_bob, bob, 7); */
    /* rtmp_harness_recv_video (h_bob, bob, 3); */

    /* fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe)); */
    /* fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe)); */

    rtmp_harness_teardown (h_abe);
  }
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_unlock_sink_bug5054)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  h->block_on_publish = TRUE;

  gint abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_AAC);
  rtmp_harness_send_audio_async (h, abe, 20, 9);

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_remove_publisher (h, abe);
  h->block_on_publish = FALSE;

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_unlock_src)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  h->block_on_play = TRUE;

  gint abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_AAC);
  rtmp_harness_send_audio (h, abe, 20, 9);
  rtmp_harness_wait_for_notified_publishers (h, 1);

  gint bob = rtmp_harness_add_subscriber (h, "test");
  rtmp_harness_add_audiosink (h, bob, RTMP_AAC);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  g_usleep (G_USEC_PER_SEC);

  rtmp_harness_remove_subscriber (h, bob);
  h->block_on_play = FALSE;

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmpsink_start_stop_start)
{
  GstHarness *h =
      gst_harness_new_parse ("rtmpsink location=rtmp://foo/bar/baz");
  GstElement *sink = h->element;
  GstState state, pending;
  g_assert (gst_element_set_state (sink, GST_STATE_NULL) ==
      GST_STATE_CHANGE_SUCCESS);
  g_assert (gst_element_get_state (sink, &state, &pending, 0) ==
      GST_STATE_CHANGE_SUCCESS);
  g_assert (state == GST_STATE_NULL);
  gst_harness_set (h, "rtmpsink", "location", "rtmp://foo/bar/baz", NULL);
  gst_harness_play (h);
  gst_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmpsink_start_stop_dns_error)
{
  GstHarness *h = gst_harness_new_parse ("rtmpsrc location=rtmp://a/b/c");
  GstElement *sink = h->element;
  GstState state, pending;
  g_assert (gst_element_set_state (sink, GST_STATE_NULL) ==
      GST_STATE_CHANGE_SUCCESS);
  g_assert (gst_element_get_state (sink, &state, &pending, 0) ==
      GST_STATE_CHANGE_SUCCESS);
  g_assert (state == GST_STATE_NULL);
  gst_harness_set (h, "rtmpsrc", "location", "rtmp://a/b/c", NULL);
  gst_harness_play (h);
  gst_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmpsink_unlock)
{
  gint fd;
  GstHarness *h;
  GTimer *timer;

  fd = tcp_listen (22006);
  h = gst_harness_new_parse
      ("queue ! rtmpsink location=rtmp://localhost:22006/app/streamname1");
  gst_harness_set_src_caps_str (h, "video/x-flv");

  timer = g_timer_new ();
  gst_harness_push (h, gst_buffer_new ());

  g_usleep (G_USEC_PER_SEC / 100 * __i__);

  gst_harness_teardown (h);
  tcp_disconnect (fd);

  fail_unless (g_timer_elapsed (timer, NULL) < 2.0);
  g_timer_destroy (timer);
}

GST_END_TEST;

GST_START_TEST (rtmpsrc_unlock)
{
  gint fd;
  GstHarness *h;
  GTimer *timer;

  fd = tcp_listen (22002);

  h = gst_harness_new_parse
      ("rtmpsrc location=rtmp://localhost:22002/app/streamname1");

  timer = g_timer_new ();
  gst_harness_play (h);

  g_print ("i = %d\n", __i__);
  g_usleep (G_USEC_PER_SEC / 100 * __i__);

  gst_harness_teardown (h);
  tcp_disconnect (fd);

  fail_unless (g_timer_elapsed (timer, NULL) < 2.0);
  g_timer_destroy (timer);
}

GST_END_TEST;

GST_START_TEST (rtmpsrc_flow_ok_on_error)
{
  gint fd;
  GstHarness *h;
  GstMessage *message;
  GstMessageType message_type;
  GstBus *bus;

  fd = tcp_listen (22004);
  bus = gst_bus_new ();
  h = gst_harness_new_parse
      ("rtmpsrc location=rtmp://localhost:22004/app/streamname1 ! fakesink");
  gst_element_set_bus (h->element, bus);
  gst_harness_play (h);
  tcp_disconnect (fd);

  while (1) {
    if ((message = gst_bus_pop (bus)) != NULL) {
      message_type = GST_MESSAGE_TYPE (message);
      if (message_type == GST_MESSAGE_ERROR) {
        GError *err = NULL;
        gchar *error_string = NULL;
        gst_message_parse_error (message, &err, &error_string);
        g_error_free (err);
        fail_unless (FALSE, "Failed after receiving message-error %s",
            error_string);
      }
      if (message_type == GST_MESSAGE_EOS) {
        gst_message_unref (message);
        break;
      }
      gst_message_unref (message);
    }
  }
  gst_element_set_bus (h->element, NULL);
  gst_object_unref (bus);
  gst_harness_teardown (h);
}

GST_END_TEST;

PEX_START_TEST_IGNORE_STATECHANGE_WARNINGS (rtmpsink_unlock_race)
{
  GstHarness *h = gst_harness_new_parse ("rtmpsink location=rtmp://a/b/c");
  GstHarnessThread *statechange, *push;
  GstSegment segment;
  GstCaps *caps = gst_caps_from_string ("video/x-flv");
  GstBuffer *buf = gst_buffer_new ();

  gst_segment_init (&segment, GST_FORMAT_TIME);

  statechange = gst_harness_stress_statechange_start_full (h, 1);
  push = gst_harness_stress_push_buffer_start (h, caps, &segment, buf);

  g_usleep (G_USEC_PER_SEC * 1);

  gst_harness_stress_thread_stop (statechange);
  gst_harness_stress_thread_stop (push);

  gst_caps_unref (caps);
  gst_buffer_unref (buf);
  gst_harness_teardown (h);
}

PEX_END_TEST;

static void
check_buf_type_timestamp (GstBuffer * buf, gint packet_type, gint timestamp)
{
  GstMapInfo map = GST_MAP_INFO_INIT;
  gst_buffer_map (buf, &map, GST_MAP_READ);
  fail_unless_equals_int (packet_type, map.data[0]);
  fail_unless_equals_int (timestamp, map.data[6]);
  gst_buffer_unmap (buf, &map);
  gst_buffer_unref (buf);
}

GST_START_TEST (rtmp_flv_timestamping_reordered)
{
  const gint AUDIO = 0x08;
  const gint VIDEO = 0x09;
  gint timestamp = 3;
  GstClockTime base_time = 42 * GST_SECOND;
  GstPad *audio_sink, *video_sink, *audio_src, *video_src;
  GstHarness *h, *audio, *video, *audio_q, *video_q;
  GstCaps *audio_caps, *video_caps;
  GstBuffer *buf;

  h = gst_harness_new_with_padnames ("flvmux", NULL, "src");
  audio = gst_harness_new_with_element (h->element, "audio", NULL);
  video = gst_harness_new_with_element (h->element, "video", NULL);
  audio_q = gst_harness_new ("queue");
  video_q = gst_harness_new ("queue");

  audio_sink = GST_PAD_PEER (audio->srcpad);
  video_sink = GST_PAD_PEER (video->srcpad);
  audio_src = GST_PAD_PEER (audio_q->sinkpad);
  video_src = GST_PAD_PEER (video_q->sinkpad);

  gst_pad_unlink (audio->srcpad, audio_sink);
  gst_pad_unlink (video->srcpad, video_sink);
  gst_pad_unlink (audio_src, audio_q->sinkpad);
  gst_pad_unlink (video_src, video_q->sinkpad);
  gst_pad_link (audio_src, audio_sink);
  gst_pad_link (video_src, video_sink);

  audio_caps = gst_caps_new_simple ("audio/x-speex",
      "rate", G_TYPE_INT, 16000, "channels", G_TYPE_INT, 1, NULL);
  gst_harness_set_src_caps (audio_q, audio_caps);
  video_caps = gst_caps_new_simple ("video/x-h264",
      "stream-format", G_TYPE_STRING, "avc", NULL);
  gst_harness_set_src_caps (video_q, video_caps);

  /* Push audio + video + audio with increasing DTS, but PTS for video is
   * GST_CLOCK_TIME_NONE
   */
  buf = gst_buffer_new ();
  GST_BUFFER_DTS (buf) = timestamp * GST_MSECOND + base_time;
  GST_BUFFER_PTS (buf) = timestamp * GST_MSECOND + base_time;
  gst_harness_push (audio_q, buf);

  buf = gst_buffer_new ();
  GST_BUFFER_DTS (buf) = (timestamp + 1) * GST_MSECOND + base_time;
  GST_BUFFER_PTS (buf) = GST_CLOCK_TIME_NONE;
  gst_harness_push (video_q, buf);

  buf = gst_buffer_new ();
  GST_BUFFER_DTS (buf) = (timestamp + 2) * GST_MSECOND + base_time;
  GST_BUFFER_PTS (buf) = (timestamp + 2) * GST_MSECOND + base_time;
  gst_harness_push (audio_q, buf);

  /* Pull two metadata packets out */
  gst_buffer_unref (gst_harness_pull (h));
  gst_buffer_unref (gst_harness_pull (h));

  /* Check that we receive the packets in monotonically increasing order and
   * that their timestamps are correct (should start at 0)
   */
  buf = gst_harness_pull (h);
  check_buf_type_timestamp (buf, AUDIO, 0);
  buf = gst_harness_pull (h);
  check_buf_type_timestamp (buf, VIDEO, 1);

  /* teardown */
  gst_harness_teardown (h);
  gst_harness_teardown (audio);
  gst_harness_teardown (video);
  gst_harness_teardown (audio_q);
  gst_harness_teardown (video_q);
}

GST_END_TEST;

GST_START_TEST (rtmp_audio_alaw_not_handled)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_audiosrc (h, abe, RTMP_ALAW);
  rtmp_harness_add_audiosink (h, bob, RTMP_ALAW);

  rtmp_harness_send_audio (h, abe, 7, 7);

  g_usleep (G_USEC_PER_SEC / 10);

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_src_port)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost",
      "127.0.0.1", 12000);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_dialout_ipv6_src_port)
{
  RTMPHarness *h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness *h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17);      /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_AAC);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_AAC);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "::1", "::1", 11001);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 20, 9);
  rtmp_harness_send_video_async (h_abe, abe, 9, 9);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 9);;

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}

GST_END_TEST;

GST_START_TEST (rtmp_multiple_publishers_dont_crash_issue_8832)
{
  RTMPHarness *h = rtmp_harness_new ("live");
  const gint num_publishers = 20;

  /* add multiple publishers and verify we don't crash */
  for (gint i = 0; i < num_publishers; i++) {
    gint p = rtmp_harness_add_publisher (h, "test");
    rtmp_harness_add_audiosrc (h, p, RTMP_AAC);
    rtmp_harness_send_audio_async (h, p, 20, 9);
  }

  rtmp_harness_teardown (h);
}

GST_END_TEST;

/* Regression test: pexrtmpsrc must reset its internal pipeline when a
 * publisher disconnects so that data from a *subsequent* publisher can flow
 * through to its audio_src/video_src ghost pads.
 *
 * Before the fix, the rtmpserversrc inside pexrtmpsrc latched into EOS when
 * the first publisher disconnected (subscribe_flv returns false -> GST_FLOW_EOS),
 * and EOS poisoned the queue->pexsync chain so that no buffers from a second
 * publisher ever made it to the ghost pads -- even though the publish_accept
 * and publish_start callbacks fired correctly. */
GST_START_TEST (rtmp_publisher_reconnect_data_keeps_flowing)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  /* The subscriber uses pexrtmpsrc internally; this is the element under test. */
  gint sub = rtmp_harness_add_subscriber (h, "live");
  rtmp_harness_set_subscriber_auto_reconnect (h, sub, TRUE);

  /* First publisher: stream some data through and verify it arrives. Wait for
   * both publisher and subscriber notifications before sending media so we
   * don't race with the connect handshake (cf. rtmp_audio_aac). */
  gint pub1 = rtmp_harness_add_publisher (h, "live");
  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_add_audiosink (h, sub, RTMP_AAC);
  rtmp_harness_add_videosink (h, sub);
  rtmp_harness_add_audiosrc (h, pub1, RTMP_AAC);
  rtmp_harness_add_videosrc (h, pub1);

  rtmp_harness_send_audio_async (h, pub1, 20, 9);
  rtmp_harness_send_video_async (h, pub1, 9, 9);

  rtmp_harness_recv_audio (h, sub, 7);
  rtmp_harness_recv_video (h, sub, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h, sub, pub1));
  fail_unless (rtmp_harness_verify_recv_video (h, sub, pub1));

  /* Disconnect the first publisher. This triggers on-publish-done, which
   * before the fix would leave pexrtmpsrc in a stuck-EOS state. */
  rtmp_harness_remove_publisher (h, pub1);
  rtmp_harness_wait_for_notified_publishers (h, 0);

  /* Second publisher on the same path: data from this publisher must still
   * make it through pexrtmpsrc to the subscriber. */
  gint pub2 = rtmp_harness_add_publisher (h, "live");
  rtmp_harness_wait_for_notified_publishers (h, 1);

  rtmp_harness_add_audiosrc (h, pub2, RTMP_AAC);
  rtmp_harness_add_videosrc (h, pub2);

  rtmp_harness_send_audio_async (h, pub2, 20, 9);
  rtmp_harness_send_video_async (h, pub2, 9, 9);

  rtmp_harness_recv_audio (h, sub, 7);
  rtmp_harness_recv_video (h, sub, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h, sub, pub2));
  fail_unless (rtmp_harness_verify_recv_video (h, sub, pub2));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

/* Regression test: a publisher disconnect on one path must NOT tear down
 * the pexrtmpsrc subscribed to a different path on the same shared
 * PexRtmpServer. Without per-path filtering on `on-publish-done`, the bin
 * would reset every time *any* publisher anywhere disconnected. */
GST_START_TEST (rtmp_publisher_disconnect_does_not_disturb_other_paths)
{
  RTMPHarness *h = rtmp_harness_new ("live");

  gint sub_a = rtmp_harness_add_subscriber (h, "path_a");
  gint sub_b = rtmp_harness_add_subscriber (h, "path_b");
  rtmp_harness_set_subscriber_auto_reconnect (h, sub_a, TRUE);
  rtmp_harness_set_subscriber_auto_reconnect (h, sub_b, TRUE);

  gint pub_a = rtmp_harness_add_publisher (h, "path_a");
  gint pub_b = rtmp_harness_add_publisher (h, "path_b");

  rtmp_harness_wait_for_notified_publishers (h, 2);
  rtmp_harness_wait_for_notified_subscribers (h, 2);

  rtmp_harness_add_audiosink (h, sub_a, RTMP_AAC);
  rtmp_harness_add_videosink (h, sub_a);
  rtmp_harness_add_audiosink (h, sub_b, RTMP_AAC);
  rtmp_harness_add_videosink (h, sub_b);

  rtmp_harness_add_audiosrc (h, pub_a, RTMP_AAC);
  rtmp_harness_add_videosrc (h, pub_a);
  rtmp_harness_add_audiosrc (h, pub_b, RTMP_AAC);
  rtmp_harness_add_videosrc (h, pub_b);

  /* Disconnect publisher on path_a; sub_a is allowed to be torn down (and
   * would re-subscribe on a future reconnect), but sub_b on path_b must
   * keep streaming undisturbed from pub_b. */
  rtmp_harness_remove_publisher (h, pub_a);
  rtmp_harness_wait_for_notified_publishers (h, 1);

  rtmp_harness_send_audio_async (h, pub_b, 20, 9);
  rtmp_harness_send_video_async (h, pub_b, 9, 9);

  rtmp_harness_recv_audio (h, sub_b, 7);
  rtmp_harness_recv_video (h, sub_b, 9);

  fail_unless (rtmp_harness_verify_recv_audio (h, sub_b, pub_b));
  fail_unless (rtmp_harness_verify_recv_video (h, sub_b, pub_b));

  rtmp_harness_teardown (h);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_src_to_sink_speex)
{
  SKIP_BROKEN_TEST_IF_MSVC;
  SKIP_BROKEN_TEST_IF_STATIC_BUILD;

  PexRtmpServer *server = pex_rtmp_server_new ("test",
      1935, 1936,
      NULL, NULL,
      NULL, NULL,
      NULL, TRUE, FALSE);
  pex_rtmp_server_start (server);

  GstHarness *recv_h = gst_harness_new_parse ("rtmpserversrc ! flvdemux");
  GstHarness *send_h =
      gst_harness_new_parse ("audiotestsrc is-live=1 samplesperbuffer=320 ! "
      "speexenc ! " "flvmux streamable=1 ! " "rtmpserversink");

  GstElement *rtmp_src = gst_harness_find_element (recv_h, "rtmpserversrc");
  GstElement *rtmp_sink = gst_harness_find_element (send_h, "rtmpserversink");
  g_object_set (rtmp_src, "server", server, "path", "test-path", NULL);
  g_object_set (rtmp_sink, "server", server, "path", "test-path", NULL);
  gst_object_unref (rtmp_src);
  gst_object_unref (rtmp_sink);

  GstElement *demux = gst_harness_find_element (recv_h, "flvdemux");
  g_signal_connect (demux, "pad-added", G_CALLBACK (flvdemux_pad_added),
      recv_h);
  gst_object_unref (demux);

  gst_harness_add_sink_parse (recv_h, "speexdec");
  gst_harness_play (recv_h);
  gst_harness_play (send_h);

  /* produce some audio-buffers */
  for (guint i = 0; i < 3; i++) {
    gst_harness_crank_single_clock_wait (send_h);
  }

  /* check that the decoder can make sense of this */
  for (guint i = 0; i < 4; i++) {
    gst_harness_push_to_sink (recv_h);
  }

  /* and check we got decoded data */
  for (guint i = 0; i < 2; i++) {
    gst_buffer_unref (gst_harness_pull (recv_h->sink_harness));
  }

  gst_harness_teardown (recv_h);
  gst_harness_teardown (send_h);
  pex_rtmp_server_stop (server);
  g_object_unref (server);
}

GST_END_TEST;

GST_START_TEST (rtmp_server_src_to_sink_aac)
{
  PexRtmpServer *server = pex_rtmp_server_new ("test",
      1935, 1936,
      NULL, NULL,
      NULL, NULL,
      NULL, TRUE, FALSE);
  pex_rtmp_server_start (server);

  GstHarness *recv_h = gst_harness_new_parse ("rtmpserversrc ! flvdemux");
  GstHarness *send_h =
      gst_harness_new_parse ("audiotestsrc is-live=1 samplesperbuffer=1024 ! "
      "pexaacenc ! " "flvmux streamable=1 ! " "rtmpserversink");

  GstElement *rtmp_src = gst_harness_find_element (recv_h, "rtmpserversrc");
  GstElement *rtmp_sink = gst_harness_find_element (send_h, "rtmpserversink");
  g_object_set (rtmp_src, "server", server, "path", "test-path", NULL);
  g_object_set (rtmp_sink, "server", server, "path", "test-path", NULL);
  gst_object_unref (rtmp_src);
  gst_object_unref (rtmp_sink);

  GstElement *demux = gst_harness_find_element (recv_h, "flvdemux");
  g_signal_connect (demux, "pad-added", G_CALLBACK (flvdemux_pad_added),
      recv_h);
  gst_object_unref (demux);

  gst_harness_add_sink_parse (recv_h, "pexaacdec");
  gst_harness_play (recv_h);
  gst_harness_play (send_h);

  /* produce some audio-buffers */
  for (guint i = 0; i < 3; i++) {
    gst_harness_crank_single_clock_wait (send_h);
  }

  /* check that the decoder can make sense of this */
  for (guint i = 0; i < 3; i++) {
    gst_harness_push_to_sink (recv_h);
    gst_buffer_unref (gst_harness_pull (recv_h->sink_harness));
  }

  gst_harness_teardown (recv_h);
  gst_harness_teardown (send_h);
  pex_rtmp_server_stop (server);
  g_object_unref (server);
}

GST_END_TEST;


GST_START_TEST (rtmp_server_src_to_server_to_sink)
{
  PexRtmpServer *server = pex_rtmp_server_new ("test",
      1935, 1936,
      NULL, NULL,
      NULL, NULL,
      NULL, TRUE, FALSE);
  pex_rtmp_server_start (server);

  GstHarness *recv_h = gst_harness_new_parse ("rtmpserversrc ! flvdemux");
  GstHarness *send_h =
      gst_harness_new_parse ("audiotestsrc is-live=1 samplesperbuffer=1024 ! "
      "pexaacenc ! " "flvmux streamable=1 ! " "rtmpserversink");

  GstElement *rtmp_src = gst_harness_find_element (recv_h, "rtmpserversrc");
  GstElement *rtmp_sink = gst_harness_find_element (send_h, "rtmpserversink");

  gchar *rtmp_url = g_strdup_printf ("rtmp://127.0.0.1:1935/app/test_path");
  g_object_set (rtmp_src, "dialin-url", rtmp_url, NULL);
  g_object_set (rtmp_sink, "dialout-url", rtmp_url, NULL);
  g_free (rtmp_url);
  gst_object_unref (rtmp_src);
  gst_object_unref (rtmp_sink);

  GstElement *demux = gst_harness_find_element (recv_h, "flvdemux");
  g_signal_connect (demux, "pad-added", G_CALLBACK (flvdemux_pad_added),
      recv_h);
  gst_object_unref (demux);

  gst_harness_add_sink_parse (recv_h, "pexaacdec");
  gst_harness_play (recv_h);
  gst_harness_play (send_h);

  /* produce some audio-buffers */
  for (guint i = 0; i < 3; i++) {
    gst_harness_crank_single_clock_wait (send_h);
  }

  /* check that the decoder can make sense of this */
  for (guint i = 0; i < 3; i++) {
    gst_harness_push_to_sink (recv_h);
  }

  /* and check we got decoded data */
  for (guint i = 0; i < 3; i++) {
    gst_buffer_unref (gst_harness_pull (recv_h->sink_harness));
  }

  gst_harness_teardown (recv_h);
  gst_harness_teardown (send_h);
  pex_rtmp_server_stop (server);
  g_object_unref (server);
}

GST_END_TEST;

GST_START_TEST (rtmp_set_certs_after_construction)
{
  PexRtmpServer *server =
      pex_rtmp_server_new ("pexip", 1935, 0, NULL, NULL, NULL, NULL, NULL,
      FALSE, FALSE);
  g_object_set (server, "cert_file", "ca.pem", "key_file", "key.pem",
      "ca_cert_dir", "certs/", "ciphers", "ciphers", "tls1-enabled", TRUE,
      NULL);
  pex_rtmp_server_start (server);
  pex_rtmp_server_stop (server);
  g_object_unref (server);
}

GST_END_TEST;

#ifndef _MSC_VER
GST_START_TEST (rtmp_tcp_get_listen_port_null_port)
{
  /* Passing NULL as the out-param is rejected with errno=EINVAL.
   * fd value is irrelevant - we should bail out before touching it. */
  errno = 0;
  fail_if (tcp_get_listen_port (-1, NULL));
  fail_unless_equals_int (EINVAL, errno);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_not_a_socket)
{
  /* A valid fd that is not a socket -> getsockname returns ENOTSOCK. */
  gint fd = open ("/dev/null", O_RDONLY);
  fail_if (fd < 0);

  gint port = 12345;
  errno = 0;
  fail_if (tcp_get_listen_port (fd, &port));
  fail_unless_equals_int (ENOTSOCK, errno);
  fail_unless_equals_int (12345, port);

  close (fd);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_unsupported_family)
{
  /* A bound UNIX-domain socket has AF_UNIX, which the function explicitly
   * rejects with EAFNOSUPPORT. This pins the default-branch contract. */
  gint fd = socket (AF_UNIX, SOCK_STREAM, 0);
  fail_if (fd < 0);

  /* bind to an autobind abstract address so we don't touch the filesystem
   * (Linux-specific). On non-Linux, skip this test. */
#ifdef __linux__
  struct sockaddr_un addr = { 0 };
  addr.sun_family = AF_UNIX;
  /* abstract namespace: leading NUL */
  fail_if (bind (fd, (struct sockaddr *) &addr, sizeof (sa_family_t)) != 0);

  gint port = 12345;
  errno = 0;
  fail_if (tcp_get_listen_port (fd, &port));
  fail_unless_equals_int (EAFNOSUPPORT, errno);
  fail_unless_equals_int (12345, port);
#endif

  close (fd);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_ipv4)
{
  /* Explicit IPv4 path: bind to 127.0.0.1:0 and verify we read back the
   * kernel-assigned port. */
  gint fd = socket (AF_INET, SOCK_STREAM, 0);
  fail_if (fd < 0);

  struct sockaddr_in addr = { 0 };
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  fail_if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) != 0);

  gint port = 0;
  fail_unless (tcp_get_listen_port (fd, &port));
  fail_if (port == 0);
  fail_unless (port > 0 && port <= G_MAXUINT16);

  close (fd);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_ipv6)
{
  /* Explicit IPv6 path: this is the bug the sockaddr_storage refactor
   * actually fixed - sockaddr was too small for sockaddr_in6. */
  gint fd = socket (AF_INET6, SOCK_STREAM, 0);
  if (fd < 0)
    return;                     /* IPv6 not available in this environment - skip */

  struct sockaddr_in6 addr = { 0 };
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_loopback;
  addr.sin6_port = 0;
  fail_if (bind (fd, (struct sockaddr *) &addr, sizeof (addr)) != 0);

  gint port = 0;
  fail_unless (tcp_get_listen_port (fd, &port));
  fail_if (port == 0);
  fail_unless (port > 0 && port <= G_MAXUINT16);

  close (fd);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_unbound_socket)
{
  /* A socket() that has not been bind()ed yet: on Linux this returns
   * a sockaddr with port 0 and succeeds. The point of this test is to
   * document the behavior so a future refactor doesn't change it silently. */
  gint fd = socket (AF_INET, SOCK_STREAM, 0);
  fail_if (fd < 0);

  gint port = -1;
  fail_unless (tcp_get_listen_port (fd, &port));
  fail_unless_equals_int (0, port);

  close (fd);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_invalid_fd)
{
  /* INVALID_FD is the documented "no listener" sentinel. Passing it must be
   * rejected with EINVAL before any getsockname() call, and must leave the
   * caller's port value untouched. */
  gint port = 12345;            /* sentinel */
  errno = 0;
  fail_if (tcp_get_listen_port (INVALID_FD, &port));
  fail_unless_equals_int (EINVAL, errno);
  fail_unless_equals_int (12345, port);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_invalid_fd_and_null_port)
{
  /* Both inputs invalid: still EINVAL, still no crash. Pins down that the
   * NULL-port and INVALID_FD checks are combined into a single guard and
   * neither is dependent on the other. */
  errno = 0;
  fail_if (tcp_get_listen_port (INVALID_FD, NULL));
  fail_unless_equals_int (EINVAL, errno);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_get_listen_port_closed_fd)
{
  /* A closed (but not INVALID_FD) descriptor: should reach getsockname()
   * and fail with EBADF. */
  gint fd = socket (AF_INET, SOCK_STREAM, 0);
  fail_if (fd < 0);
  close (fd);

  gint port = 12345;
  errno = 0;
  fail_if (tcp_get_listen_port (fd, &port));
  fail_unless_equals_int (EBADF, errno);
  fail_unless_equals_int (12345, port);
}

GST_END_TEST;

GST_START_TEST (rtmp_tcp_is_localhost_ipv6)
{
  gint listen_fd = socket (AF_INET6, SOCK_STREAM, 0);
  if (listen_fd < 0)
    return;                     /* IPv6 not available */

  struct sockaddr_in6 addr = { 0 };
  addr.sin6_family = AF_INET6;
  addr.sin6_addr = in6addr_loopback;
  addr.sin6_port = 0;

  fail_if (bind (listen_fd, (struct sockaddr *) &addr, sizeof (addr)) != 0);
  fail_if (listen (listen_fd, 1) != 0);

  socklen_t len = sizeof (addr);
  fail_if (getsockname (listen_fd, (struct sockaddr *) &addr, &len) != 0);

  gint client_fd = socket (AF_INET6, SOCK_STREAM, 0);
  fail_if (client_fd < 0);
  fail_if (connect (client_fd, (struct sockaddr *) &addr, sizeof (addr)) != 0);

  gint server_fd = accept (listen_fd, NULL, NULL);
  fail_if (server_fd < 0);

  /* This is the regression check for the AF_INET6 path. */
  fail_unless (tcp_is_localhost (server_fd));

  close (client_fd);
  close (server_fd);
  close (listen_fd);
}

GST_END_TEST;
#endif /* _MSC_VER */

static Suite *
rtmp_suite (void)
{
  Suite *s = suite_create ("rtmp");

  TCase *tc_chain = tcase_create ("general");
  tcase_add_checked_fixture (tc_chain, rtmp_setup, rtmp_teardown);
  suite_add_tcase (s, tc_chain);

  tcase_add_test (tc_chain, rtmp_speex_flv_end_to_end);

  /* These two assert exact, zero-latency FLV/speex output timestamps. They
   * pass with the pexip-patched speexenc ("speexenc: Don't set lookahead", see
   * the note in rtmpharness.c), but a stock upstream speexenc adds a constant
   * ~8.94 ms encoder look-ahead to every buffer, so the i*20ms expectation is
   * off by a fixed offset. Skipped (rather than adjusted) so the very same
   * sources keep matching the pexip/media copy. */
  tcase_skip_broken_loop_test (tc_chain, rtmp_flv_timestamping,
      0, G_N_ELEMENTS (rtmp_flv_timestamping_data));
  tcase_skip_broken_test (tc_chain, rtmp_flv_timestamping_with_valve);

  tcase_add_test (tc_chain, rtmp_flv_aac);

  tcase_add_test (tc_chain, flvdemux_sends_caps_events);

  tcase_add_test (tc_chain, rtmp_audio_speex);
  tcase_add_test (tc_chain, rtmp_audio_aac);
  tcase_add_test (tc_chain, rtmp_audio_mp3_not_supported);
  tcase_add_loop_test (tc_chain, rtmp_audio_before_subscriber, 0, 2);

  tcase_add_test (tc_chain, rtmp_video);
  tcase_add_test (tc_chain, rtmp_audio_and_video);
  tcase_add_test (tc_chain, rtmp_multiple_paths);

/* should we move these? */
#if !defined(_MSC_VER)
  tcase_add_test (tc_chain, rtmp_flash_handshake);
  tcase_add_test (tc_chain, rtmp_amf3_object_parsing);
  tcase_add_test (tc_chain, rtmp_amf3_coverity_add_int);
  tcase_add_test (tc_chain, rtmp_amf0_object_parsing);
  tcase_add_test (tc_chain, rtmp_amf0_object_parsing_wowza_connect);
  tcase_add_test (tc_chain, rtmp_amf0_ecma_array_parsing);
  tcase_add_test (tc_chain, rtmp_amf_issue_4512);
  tcase_add_test (tc_chain, rtmp_amf_unicode_issue_20402);
  tcase_add_test (tc_chain, rtmp_amf_dec_fuzzing);
  tcase_add_test (tc_chain, rtmp_amf_null_object);
  tcase_add_test (tc_chain, rtmp_window_size);
#endif /* _MSC_VER */

  tcase_add_test (tc_chain, rtmp_server_get_port_dynamic);
  tcase_add_test (tc_chain, rtmp_server_get_ssl_port_dynamic);
  tcase_add_test (tc_chain, rtmp_server_get_port_dynamic_both);
  tcase_add_test (tc_chain, rtmp_server_get_port_unset);
  tcase_add_test (tc_chain, rtmp_server_get_port_before_start);

  tcase_add_loop_test (tc_chain, rtmp_server_url_parse, 0,
      G_N_ELEMENTS (rtmp_parse_data));

  tcase_add_test (tc_chain, rtmp_server_dialout);
  tcase_add_test (tc_chain, rtmp_server_dialout_ipv6);
  tcase_add_loop_test (tc_chain, rtmp_server_dialout_src_port, 0, 2);
  tcase_add_loop_test (tc_chain, rtmp_server_dialout_ipv6_src_port, 0, 2);
  tcase_add_test (tc_chain, rtmp_server_dialout_ip_list);
  tcase_add_test (tc_chain, rtmp_server_dialout_tcp_disconnect_tcp);

  tcase_add_test (tc_chain, rtmp_server_dialout_adobe_auth_success);
  tcase_add_test (tc_chain, rtmp_server_dialout_adobe_auth_with_srcport);
  tcase_add_test (tc_chain,
      rtmp_server_dialout_adobe_auth_fail_wrong_credentials);
  tcase_add_test (tc_chain, rtmp_server_dialout_adobe_auth_fail_no_credentials);

  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_cn_dns);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_san_dns);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_cn_ip);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_san_ip);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_san_mismatch);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_no_trust);
  tcase_add_test (tc_chain, rtmp_server_dialout_ecdh);

  tcase_add_test (tc_chain, rtmp_server_dialin);
  tcase_add_test (tc_chain, rtmp_server_dialin_and_dialout_speex);
  tcase_add_test (tc_chain, rtmp_server_dialin_and_dialout_aac);

#ifdef __APPLE__
  (void) rtmp_server_dialout_dead_host_bug_4130;
#else
  tcase_add_test (tc_chain, rtmp_server_dialout_dead_host_bug_4130);
#endif

  tcase_add_test (tc_chain, rtmp_extended_timestamp);

  tcase_add_test (tc_chain, rtmp_nonblocking_handshake);
  tcase_add_test (tc_chain, rtmps_nonblocking_handshake);
  tcase_add_test (tc_chain, rtmp_nonblocking_outgoing_handshake);
  tcase_add_test (tc_chain, rtmp_connect_can_be_cancelled);
  tcase_add_test (tc_chain, rtmp_nonblocking_connect);

  tcase_add_test (tc_chain, rtmp_server_stress_bug_4648);

  tcase_add_test (tc_chain, rtmp_server_ignore_localhost);
  tcase_add_test (tc_chain, rtmp_server_stress_bug_5467);

  tcase_skip_broken_test (tc_chain, rtmpsrc_flow_ok_on_error);
  tcase_skip_broken_test (tc_chain, rtmpsink_start_stop_start);
  tcase_skip_broken_test (tc_chain, rtmpsink_start_stop_dns_error);
  tcase_skip_broken_loop_test (tc_chain, rtmpsink_unlock, 0, 20);
  tcase_skip_broken_loop_test (tc_chain, rtmpsrc_unlock, 0, 20);
  tcase_skip_broken_test (tc_chain, rtmpsink_unlock_race);

  tcase_add_test (tc_chain, rtmp_flv_timestamping_reordered);
  tcase_add_test (tc_chain, rtmp_audio_alaw_not_handled);

  tcase_add_test (tc_chain, rtmp_server_src_to_sink_speex);
  tcase_add_test (tc_chain, rtmp_server_src_to_sink_aac);
  tcase_add_test (tc_chain, rtmp_server_src_to_server_to_sink);

  /* these no longer makes sense */
  tcase_skip_broken_test (tc_chain, rtmp_unlock_sink_bug5054);
  tcase_skip_broken_test (tc_chain, rtmp_unlock_src);

  //tcase_add_test (tc_chain, rtmp_server_dialout_close_tcp);
  /* Correct, but pathologically slow against a stock upstream server: it drives
   * a 3-node dial-out/dial-in chain with chunk-size 1, and the server's fixed
   * 200 ms poll granularity turns every 1-byte chunk into a poll cycle, so the
   * test takes >10 min (well past the suite timeout). Skipped here; the poll
   * loop lives in src/ and is intentionally left untouched. */
  tcase_skip_broken_test (tc_chain, rtmp_server_dialout_and_dialin_issue_14907);
  tcase_add_test (tc_chain, rtmp_one_publisher_n_subscribers);
  tcase_add_test (tc_chain, rtmp_multiple_publishers_dont_crash_issue_8832);
  tcase_add_test (tc_chain, rtmp_publisher_reconnect_data_keeps_flowing);
  tcase_add_test (tc_chain,
      rtmp_publisher_disconnect_does_not_disturb_other_paths);

  tcase_add_test (tc_chain, rtmp_set_certs_after_construction);

#if !defined(_MSC_VER)
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_null_port);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_not_a_socket);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_unsupported_family);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_ipv4);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_ipv6);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_unbound_socket);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_invalid_fd);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_invalid_fd_and_null_port);
  tcase_add_test (tc_chain, rtmp_tcp_get_listen_port_closed_fd);
  tcase_add_test (tc_chain, rtmp_tcp_is_localhost_ipv6);
#endif

  return s;
}

PEX_CHECK_MAIN_WITH_ENV (rtmp, "GST_DEBUG", "WARN,check*:DEBUG,*rtmp*:INFO")
