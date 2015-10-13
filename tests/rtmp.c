#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pextest.h"
#include <gst/check/gstcheck.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "rtmpharness.h"

#include "handshake_packet.h"
#include "wowza_connect.h"
#include "handshake.h"
#include "amf.h"
#include "client.h"
#include <arpa/inet.h>
#include "rtmp.h"
#include <unistd.h>


static void
rtmp_setup(void)
{
  SSL_load_error_strings ();
  SSL_library_init ();
  OpenSSL_add_all_digests ();
}

static void
rtmp_teardown(void)
{
  EVP_cleanup ();
}

static void
array_from_element_cb (GstElement * sink,
    GValueArray * array, GValueArray ** array_cpy)
{
  (void)sink;
  if (*array_cpy != NULL)
    g_value_array_free (*array_cpy);
  *array_cpy = g_value_array_copy (array);
}

static void
flvdemux_pad_added (GstElement * flvdemux, GstPad * srcpad, GstHarness * h)
{
  (void)flvdemux;
  gst_harness_add_element_srcpad (h, srcpad);
}

GST_START_TEST(rtmp_speex_flv_end_to_end)
{
  GstHarness * h = gst_harness_new_parse (
    "pexaudioconvert ! speexenc ! flvmux streamable=1 ! flvdemux");

  gst_harness_add_src (h, "pexcisionaudiosrc", TRUE);
  g_object_set (h->src_harness->element,
      "mode", 1, "freq", 900.0, "samplesperbuffer", 960, NULL);

  h->sink_harness = gst_harness_new_parse (
      "speexdec ! pexaudioconvert ! pexcisionaudiosink");

  /* configure the sink */
  GValueArray * freq_list = NULL;
  GstElement * sink = gst_harness_find_element (h->sink_harness, "pexcisionaudiosink");
  g_signal_connect (sink,
      "freq-list", G_CALLBACK (array_from_element_cb), &freq_list);
  g_object_set (sink,
      "fft-mag-threshold", -25.0,
      "fft-required-samples", 960, NULL);
  gst_object_unref (sink);

  GstElement * flvdemux = gst_harness_find_element (h, "flvdemux");
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

GST_START_TEST(rtmp_flv_timestamping_basics)
{
  GstHarness * h = gst_harness_new_with_padnames ("flvdemux", "sink", NULL);
  h->src_harness = gst_harness_new_parse (
      "pexcisionaudiosrc samplesperbuffer=960 ! pexaudioconvert ! "
      "speexenc ! flvmux streamable=1");
  g_signal_connect (h->element, "pad-added", G_CALLBACK (flvdemux_pad_added), h);

  gst_harness_use_testclock (h->src_harness);
  gst_harness_play (h->src_harness);

  gst_harness_src_crank_and_push_many (h, 1, 5);
  for (int i = 0; i < 3; i++) {
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (0, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  for (int i = 1; i < 10; i++) {
    gst_harness_src_crank_and_push_many (h, 1, 1);
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (i * 20 * GST_MSECOND, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  gst_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_flv_timestamping_into_running_pipeline)
{
  GstHarness * h = gst_harness_new_with_padnames ("flvdemux", "sink", NULL);
  h->src_harness = gst_harness_new_parse (
      "pexcisionaudiosrc samplesperbuffer=960 ! pexaudioconvert ! "
      "speexenc ! flvmux streamable=1");
  g_signal_connect (h->element, "pad-added", G_CALLBACK (flvdemux_pad_added), h);

  const GstClockTime send_time = 0;
  const GstClockTime recv_time = 2 * GST_SECOND;

  gst_harness_use_testclock (h->src_harness);
  gst_harness_set_time (h->src_harness, send_time);

  gst_harness_use_testclock (h);
  gst_harness_set_time (h, recv_time);

  gst_harness_src_crank_and_push_many (h, 1, 5);
  for (int i = 0; i < 3; i++) {
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (recv_time, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  for (int i = 1; i < 10; i++) {
    gst_harness_src_crank_and_push_many (h, 1, 1);
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (recv_time + i * 20 * GST_MSECOND, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  gst_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_flv_timestamping_from_running_pipeline)
{
  GstHarness * h = gst_harness_new_with_padnames ("flvdemux", "sink", NULL);
  h->src_harness = gst_harness_new_parse (
      "pexcisionaudiosrc samplesperbuffer=960 ! pexaudioconvert ! "
      "speexenc ! flvmux streamable=1");
  g_signal_connect (h->element, "pad-added", G_CALLBACK (flvdemux_pad_added), h);

  const GstClockTime send_time = 2 * GST_SECOND;
  const GstClockTime recv_time = 0;

  gst_harness_use_testclock (h->src_harness);
  gst_harness_set_time (h->src_harness, send_time);

  gst_harness_use_testclock (h);
  gst_harness_set_time (h, recv_time);

  gst_harness_src_crank_and_push_many (h, 1, 5);
  for (int i = 0; i < 3; i++) {
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (recv_time, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  for (int i = 1; i < 10; i++) {
    gst_harness_src_crank_and_push_many (h, 1, 1);
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (recv_time + i * 20 * GST_MSECOND, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  gst_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_flv_timestamping_with_gap)
{
  GstHarness * h = gst_harness_new_with_padnames ("flvdemux", "sink", NULL);
  h->src_harness = gst_harness_new_parse (
      "pexcisionaudiosrc samplesperbuffer=960 ! pexaudioconvert ! "
      "speexenc ! flvmux streamable=1");
  g_signal_connect (h->element, "pad-added", G_CALLBACK (flvdemux_pad_added), h);

  const gint buffer_gap = 100;
  const GstClockTime send_time = 0;
  const GstClockTime recv_time = 0;

  gst_harness_use_testclock (h->src_harness);
  gst_harness_set_time (h->src_harness, send_time);

  gst_harness_use_testclock (h);
  gst_harness_set_time (h, recv_time);

  gst_harness_src_crank_and_push_many (h, 1, 5);
  for (int i = 0; i < 3; i++) {
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (recv_time, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  /* create a gap of 2 seconds */
  for (int i = 0; i < buffer_gap - 1; i++) {
    gst_harness_crank_single_clock_wait (h->src_harness);
    gst_buffer_unref (gst_harness_pull (h->src_harness));
  }

  for (int i = buffer_gap; i < buffer_gap + 10; i++) {
    gst_harness_src_crank_and_push_many (h, 1, 1);
    GstBuffer * buf = gst_harness_pull (h);
    fail_unless_equals_int64 (recv_time + i * 20 * GST_MSECOND, GST_BUFFER_TIMESTAMP (buf));
    gst_buffer_unref (buf);
  }

  gst_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_flv_aac)
{
  GstHarness * h = gst_harness_new_parse (
      "pexcisionaudiosrc samplesperbuffer=960 ! pexaudioconvert ! "
      "pexaacenc ! flvmux streamable=1");
  gst_harness_use_testclock (h);
  gst_harness_play (h);

  /* first buffers are generic FLV header stuff */
  gst_harness_crank_single_clock_wait (h);
  gst_harness_crank_single_clock_wait (h);
  gst_buffer_unref (gst_harness_pull (h));
  gst_buffer_unref (gst_harness_pull (h));

  /* third buffer is interesting, as it contains some audio-information */
  GstBuffer * buf = gst_harness_pull (h);
  guint8 * data = GST_BUFFER_DATA (buf);

  /* 0x08 means it is audio */
  fail_unless_equals_int (0x08, data[0]);

  /* 0xaf means AAC, 44.1KHz, Stereo, bullshit but needed... */
  fail_unless_equals_int (0xaf, data[11]);

  /* 0x00 here means we have an ASC coming next... */
  fail_unless_equals_int (0x00, data[12]);

  /* 0x11 0x88 is the AAC Audio Specific Config (ASC), meaning AAC-LC, 48Khz, Mono */
  fail_unless_equals_int (0x11, data[13]);
  fail_unless_equals_int (0x88, data[14]);
  gst_buffer_unref (buf);

  /* fourth buffer gets us some real encoded data */
  buf = gst_harness_pull (h);
  data = GST_BUFFER_DATA (buf);

  /* audio + AAC bullshit byte */
  fail_unless_equals_int (0x08, data[0]);
  fail_unless_equals_int (0xaf, data[11]);

  /* but there should also be a special AAC-byte added just after the 0xaf */
  fail_unless_equals_int (0x01, data[12]);
  gst_buffer_unref (buf);

  gst_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_audio_speex)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);

  rtmp_harness_send_audio (h, abe, 7, 7);
  rtmp_harness_recv_audio (h, bob, 6);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_audio_aac)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_AAC);
  rtmp_harness_add_audiosink (h, bob, RTMP_AAC);

  rtmp_harness_send_audio (h, abe, 20, 9);
  rtmp_harness_recv_audio (h, bob, 7);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_video)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_add_videosrc (h, abe);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_video (h, abe, 5, 4);
  rtmp_harness_recv_video (h, bob, 1);

  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_audio_and_video)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h, abe);

  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_audio_async (h, abe, 6, 8);
  rtmp_harness_send_video_async (h, abe, 5, 4);

  rtmp_harness_recv_audio (h, bob, 7);
  rtmp_harness_recv_video (h, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_audio_and_video_ssl)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher_ssl (h, "test");
  gint bob = rtmp_harness_add_subscriber_ssl (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h, abe);

  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_audio_async (h, abe, 6, 8);
  rtmp_harness_send_video_async (h, abe, 5, 4);

  rtmp_harness_recv_audio (h, bob, 7);
  rtmp_harness_recv_video (h, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_audio_and_video_rtmp_to_rtmps)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher_ssl (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h, abe);

  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_audio_async (h, abe, 6, 8);
  rtmp_harness_send_video_async (h, abe, 5, 4);

  rtmp_harness_recv_audio (h, bob, 7);
  rtmp_harness_recv_video (h, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_audio_and_video_rtmps_to_rtmp)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber_ssl (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h, abe);

  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_audio_async (h, abe, 6, 8);
  rtmp_harness_send_video_async (h, abe, 5, 4);

  rtmp_harness_recv_audio (h, bob, 7);
  rtmp_harness_recv_video (h, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_one_publisher_n_subscribers)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h, abe);

  const gint n = 10;
  gint * bob = g_new0 (gint, n);
  for (gint i = 0; i < n; i++)
    bob[i] = rtmp_harness_add_subscriber (h, "test");

  for (gint i = 0; i < n; i++) {
    rtmp_harness_add_audiosink (h, bob[i], RTMP_SPEEX);
    rtmp_harness_add_videosink (h, bob[i]);
  }

  rtmp_harness_send_audio_async (h, abe, 6, 8);
  rtmp_harness_send_video_async (h, abe, 5, 4);

  for (gint i = 0; i < n; i++) {
    rtmp_harness_recv_audio (h, bob[i], 7);
    rtmp_harness_recv_video (h, bob[i], 4);

    rtmp_harness_verify_recv_audio (h, bob[i], abe);
    rtmp_harness_verify_recv_video (h, bob[i], abe);
  }

  g_free (bob);
  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_multiple_paths)
{
  RTMPHarness * h = rtmp_harness_new ("live");
  const gint n = 10;

  gint * abe = g_new0 (gint, n);
  gint * bob = g_new0 (gint, n);

  for (gint i = 0; i < n; i++) {
    gchar * path = g_strdup_printf ("path_%d", i);
    abe[i] = rtmp_harness_add_publisher (h, path);
    bob[i] = rtmp_harness_add_subscriber (h, path);
    g_free (path);
  }

  for (gint i = 0; i < n; i++) {
    rtmp_harness_add_audiosrc (h, abe[i], RTMP_SPEEX);
    rtmp_harness_add_videosrc (h, abe[i]);
    rtmp_harness_add_audiosink (h, bob[i], RTMP_SPEEX);
    rtmp_harness_add_videosink (h, bob[i]);
  }

  for (gint i = 0; i < n; i++) {
    rtmp_harness_send_audio_async (h, abe[i], 6, 8);
    rtmp_harness_send_video_async (h, abe[i], 5, 4);
  }

  for (gint i = 0; i < n; i++) {
    rtmp_harness_recv_audio (h, bob[i], 7);
    rtmp_harness_recv_video (h, bob[i], 4);

    rtmp_harness_verify_recv_audio (h, bob[i], abe[i]);
    rtmp_harness_verify_recv_video (h, bob[i], abe[i]);
  }

  g_free (abe);
  g_free (bob);
  rtmp_harness_teardown (h);
}
GST_END_TEST

GST_START_TEST(rtmp_audio_automatic_reconnect)
{
  RTMPHarness * h = rtmp_harness_new ("live");
  /* setup */
  gint abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  gint bob = rtmp_harness_add_subscriber (h, "test");
  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);

  /* verfy media through */
  rtmp_harness_send_audio (h, abe, 6, 8);
  rtmp_harness_recv_audio (h, bob, 7);
  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  /* stop the server (emulating network outage or something...) */
  rtmp_harness_stop_server (h);

  /* src should disconnect right away */
  fail_unless (rtmp_harness_wait_for_rtmpsrc_connection (h, bob, FALSE));

  /* keep sending buffers until the sink notices the disconnect */
  while (rtmp_harness_get_rtmpsink_connection (h, abe) == TRUE)
    rtmp_harness_send_audio (h, abe, 1, 1);

  /* start the server up again */
  rtmp_harness_start_server (h);

  /* start up the src again (it is idling after error */
  rtmp_harness_restart_rtmpsrc (h, abe);

  /* verify we can still get media through */
  rtmp_harness_send_audio (h, abe, 17, 17);
  rtmp_harness_recv_audio (h, bob, 6);
  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_flash_handshake)
{
  PexRtmpHandshake * hs = pex_rtmp_handshake_new ();

  pex_rtmp_handshake_process (hs,
      rtmp_handshake_client_packet, sizeof (rtmp_handshake_client_packet));

  guint8 * server_handshake = pex_rtmp_handshake_get_buffer (hs);
  gint length = pex_rtmp_handshake_get_length (hs);

  fail_unless_equals_int (sizeof (expected_rtmp_handshake_server_packet), length);
  fail_unless_equals_int (0,
      memcmp (server_handshake, expected_rtmp_handshake_server_packet, length));

  pex_rtmp_handshake_free (hs);
}
GST_END_TEST;

GST_START_TEST(rtmp_amf3_object_parsing)
{
  guint8 amf3_object [] = {
    0x11, // AMF3
    0x0a, // AMF3_OBJECT
    0x0b, // object element count ?

    0x01, // start

    0x17, // stringlength 0x17 == 23, 23 - 1 / 2 = 11 == strlen ("hasmetadata")
    0x68, 0x61, 0x73, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, //"hasMetadata"
    0x03, // AMF3_TRUE

    0x21, // stringlength
    0x6b, 0x65, 0x79, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, // "keyFrameInterval"
    0x04, // AMF3_INTEGER
    0x30, // (0x30 == 48 == keyframeinterval)

    0x19, // stringlength
    0x76, 0x69, 0x64, 0x65, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69, 0x64, // "videocodecid"
    0x04, // AMF3_INTEGER
    0x07, // videocodecid == 7

    0x0b, // stringlength
    0x77, 0x69, 0x64, 0x74, 0x68, // "width"
    0x04, // AMF3_INTEGER
    0x85, 0x00,

    0x0b, // stringlength
    0x6c, 0x65, 0x76, 0x65, 0x6c, // "level"
    0x06, // AMF3_STRING
    0x07, // stringlength
    0x33, 0x2e, 0x31, // "3.1"

    0x0b, // stringlength
    0x63, 0x6f, 0x64, 0x65, 0x63, // "codec"
    0x06, // AMF3_STRING
    0x0f, // stringlength
    0x48, 0x32, 0x36, 0x34, 0x41, 0x76, 0x63, // "H264Avc"

    0x11,  // stringlength
    0x62, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x74, 0x68, // "bandwith"
    0x04, // AMF3_INTEGER
    0x85, 0xee, 0x00,

    0x0d, // stringlength
    0x68, 0x65, 0x69, 0x67, 0x68, 0x74, // "height"
    0x04, // AMF3_INTEGER
    0x83, 0x60,

    0x0f, // stringlength
    0x70, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, // "profile"
    0x06, // AMF3_STRING
    0x11, // stringlength
    0x62, 0x61, 0x73, 0x65, 0x6c, 0x69, 0x6e, 0x65, // "baseline"

    0x07, // stringlength
    0x66, 0x70, 0x73, // "fps"
    0x04, // AMF3_INTEGER
    0x1e, // 30

    0x01, // end bit?
  };

  GByteArray * buf = g_byte_array_new ();
  g_byte_array_append (buf, amf3_object, sizeof (amf3_object));
  AmfDec * dec = amf_dec_new (buf, 0);
  GstStructure * s = amf_dec_load_object (dec);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);

  gint keyFrameInterval;
  fail_unless (gst_structure_get_int (s, "keyFrameInterval", &keyFrameInterval));
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
  AmfEnc * enc = amf_enc_new ();
  amf_enc_use_amf3 (enc);
  amf_enc_write_object (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (amf3_object), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, amf3_object, sizeof (amf3_object)));
  amf_enc_free (enc);

  gst_structure_free (s);
}
GST_END_TEST;


GST_START_TEST(rtmp_amf0_object_parsing)
{
  guint8 amf0_object [] = {
    0x03, 0x00, 0x06, /* aData... */
    0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x02, 0x00, /* Server.. */
    0x2e, 0x4e, 0x47, 0x49, 0x4e, 0x58, 0x20, 0x52, /* .NGINX R */
    0x54, 0x4d, 0x50, 0x20, 0x28, 0x67, 0x69, 0x74, /* TMP (git */
    0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, /* hub.com/ */
    0x61, 0x72, 0x75, 0x74, 0x2f, 0x6e, 0x67, 0x69, /* arut/ngi */
    0x6e, 0x78, 0x2d, 0x72, 0x74, 0x6d, 0x70, 0x2d, /* nx-rtmp- */
    0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x29, 0x00, /* module). */
    0x05, 0x77, 0x69, 0x64, 0x74, 0x68, 0x00, 0x40, /* .width.@ */
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x06, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x00, /* .height. */
    0x40, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* @~...... */
    0x00, 0x0c, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, /* ..displa */
    0x79, 0x57, 0x69, 0x64, 0x74, 0x68, 0x00, 0x40, /* yWidth.@ */
    0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x0d, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, /* .display */
    0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x00, 0x40, /* Height.@ */
    0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ~....... */
    0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, /* .duratio */
    0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* n....... */
    0x00, 0x00, 0x00, 0x09, 0x66, 0x72, 0x61, 0x6d, /* ....fram */
    0x65, 0x72, 0x61, 0x74, 0x65, 0x00, 0x40, 0x3e, /* erate.@> */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, /* ........ */
    0x66, 0x70, 0x73, 0x00, 0x40, 0x3e, 0x00, 0x00, /* fps.@>.. */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x76, 0x69, /* ......vi */
    0x64, 0x65, 0x6f, 0x64, 0x61, 0x74, 0x61, 0x72, /* deodatar */
    0x61, 0x74, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, /* ate..... */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x76, 0x69, /* ......vi */
    0x64, 0x65, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, /* deocodec */
    0x69, 0x64, 0x00, 0x40, 0x1c, 0x00, 0x00, 0x00, /* id.@.... */
    0x00, 0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x64, /* .....aud */
    0x69, 0x6f, 0x64, 0x61, 0x74, 0x61, 0x72, 0x61, /* iodatara */
    0x74, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* te...... */
    0x00, 0x00, 0x00, 0x00, 0x0c, 0x61, 0x75, 0x64, /* .....aud */
    0x69, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69, /* iocodeci */
    0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* d....... */
    0x00, 0x00, 0x00, 0x07, 0x70, 0x72, 0x6f, 0x66, /* ....prof */
    0x69, 0x6c, 0x65, 0x02, 0x00, 0x08, 0x62, 0x61, /* ile.. ba */
    0x73, 0x65, 0x6c, 0x69, 0x6e, 0x65, /* seline.. */
    0x00, 0x05, /* ........ */
    0x6c, 0x65, 0x76, 0x65, 0x6c, 0x02, 0x00, 0x03, /* level..  */
    0x33, 0x2e, 0x31,  /* 3.1..... */
    0x00, 0x00, 0x09
  };

  GByteArray * buf = g_byte_array_new ();
  g_byte_array_append (buf, amf0_object, sizeof (amf0_object));
  AmfDec * dec = amf_dec_new (buf, 0);
  GstStructure * s = amf_dec_load_object (dec);
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
  AmfEnc * enc = amf_enc_new ();
  amf_enc_write_object (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (amf0_object), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, amf0_object, sizeof (amf0_object)));
  amf_enc_free (enc);

  gst_structure_free (s);
}
GST_END_TEST;

GST_START_TEST(rtmp_amf0_object_parsing_wowza_connect)
{
  GByteArray * buf = g_byte_array_new ();
  g_byte_array_append (buf, wowza_packet, sizeof (wowza_packet));
  AmfDec * dec = amf_dec_new (buf, 0);
  GstStructure * s = amf_dec_load_object (dec);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);

  /* now try to re-encode it */
  AmfEnc * enc = amf_enc_new ();
  amf_enc_write_object (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (wowza_packet), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, wowza_packet, sizeof (wowza_packet)));
  amf_enc_free (enc);

  gst_structure_free (s);
}
GST_END_TEST;


GST_START_TEST(rtmp_amf0_ecma_array_parsing)
{
  guint8 amf0_ecma_array [] = {
    0x08, 0x00, 0x00, 0x00, 0x06, 0x00, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00,
    0x40, 0xf5, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x66, 0x69, 0x6c, 0x65, 0x73, 0x69,
    0x7a, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x67, 0x73, 0x74,
    0x66, 0x69, 0x6c, 0x6c, 0x65, 0x72, 0x02, 0x09, 0x25, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x0c,
    0x61, 0x75, 0x64, 0x69, 0x6f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x69, 0x64, 0x00, 0x40, 0x26, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x63,
    0x72, 0x65, 0x61, 0x74, 0x6f, 0x72, 0x02, 0x00, 0x13, 0x47, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d,
    0x65, 0x72, 0x20, 0x46, 0x4c, 0x56, 0x20, 0x6d, 0x75, 0x78, 0x65, 0x72, 0x00, 0x0c, 0x63, 0x72,
    0x65, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x64, 0x61, 0x74, 0x65, 0x02, 0x00, 0x18, 0x54, 0x68, 0x75,
    0x20, 0x53, 0x65, 0x70, 0x20, 0x32, 0x35, 0x20, 0x31, 0x38, 0x3a, 0x35, 0x30, 0x3a, 0x31, 0x37,
    0x20, 0x32, 0x30, 0x31, 0x34, 0x00, 0x00, 0x09,
  };

  GByteArray * buf = g_byte_array_new ();
  g_byte_array_append (buf, amf0_ecma_array, sizeof (amf0_ecma_array));
  AmfDec * dec = amf_dec_new (buf, 0);
  GstStructure * s = amf_dec_load_object (dec);
  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);

  gdouble duration;
  fail_unless (gst_structure_get_double (s, "duration", &duration));
  fail_unless_equals_int (86400, (gint)duration);

  gdouble filesize;
  fail_unless (gst_structure_get_double (s, "filesize", &filesize));
  fail_unless_equals_int (0, (gint)filesize);

  /* now try to re-encode it */
  AmfEnc * enc = amf_enc_new ();
  amf_enc_write_ecma (enc, s);

  /* and verify it is identical to the original */
  fail_unless_equals_int (sizeof (amf0_ecma_array), enc->buf->len);
  fail_unless_equals_int (0, memcmp (enc->buf->data, amf0_ecma_array, sizeof (amf0_ecma_array)));

  amf_enc_free (enc);
  gst_structure_free (s);
}
GST_END_TEST;

static gint
_load_integer (AmfDec * dec)
{
  gint val;
  g_assert (amf_dec_load_integer (dec, &val));
  return val;
}

GST_START_TEST(rtmp_amf3_coverity_add_int)
{
  AmfEnc * enc = amf_enc_new ();
  amf_enc_use_amf3 (enc);
  amf_enc_add_int (enc, 5);
  amf_enc_add_int (enc, 255);
  amf_enc_add_int (enc, 16532);
  amf_enc_add_int (enc, 268435455);
  amf_enc_add_int (enc, 2147483648);
  AmfDec * dec = amf_dec_new (enc->buf, 0);

  /* and verify it is identical to the original */
  fail_unless_equals_int (_load_integer (dec), 5);
  fail_unless_equals_int (_load_integer (dec), 255);
  fail_unless_equals_int (_load_integer (dec), 16532);
  fail_unless_equals_int (_load_integer (dec), 268435455);
  fail_unless_equals_int (_load_integer (dec), 0);
  amf_enc_free (enc);
  amf_dec_free (dec);
}
GST_END_TEST;

GST_START_TEST(rtmp_amf_issue_4512)
{
  /* we need the server for GstDebugCategory */
  RTMPHarness * h = rtmp_harness_new ("live");

  guint8 rtmp_msg [] = {
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

  GByteArray * buf = g_byte_array_new ();
  g_byte_array_append (buf, rtmp_msg, sizeof (rtmp_msg));
  AmfDec * dec = amf_dec_new (buf, 0);

  gchar * type = amf_dec_load_string (dec);
  fail_unless_equals_int (0, g_strcmp0 (type, "@setDataFrame"));
  g_free (type);

  type = amf_dec_load_string (dec);
  fail_unless_equals_int (0, g_strcmp0 (type, "onMetaData"));
  g_free (type);

  GstStructure * s = amf_dec_load_object (dec);
  gst_structure_free (s);

  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);
  rtmp_harness_teardown (h);
}
GST_END_TEST;

static GByteArray *
generate_random_data (GRand * rand)
{
  GByteArray * buf = g_byte_array_new ();
  guint length = g_rand_int_range (rand, 0, 128);
  buf = g_byte_array_set_size (buf, length);

  for (guint i = 0; i < length; i++)
    buf->data[i] = g_rand_int_range (rand, 0, G_MAXUINT8);

  return buf;
}

GST_START_TEST(rtmp_amf_dec_fuzzing)
{
  /* we need the server for GstDebugCategory */
  RTMPHarness * h = rtmp_harness_new ("live");
  GRand * rand = g_rand_new_with_seed (42);

  for (gint i = 0; i < 100/*000000*/; i++) {
    GByteArray * buf = generate_random_data (rand);
    AmfDec * dec = amf_dec_new (buf, 0);

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

GST_START_TEST(rtmp_window_size)
{
  PexRtmpServer * server = pex_rtmp_server_new("pexip", 1935, 0, NULL, NULL, NULL, NULL, NULL, FALSE);
  pex_rtmp_server_start (server);
  Connections * connections = connections_new ();
  Client * client = client_new (0, connections, (GObject *)server, FALSE, 1337, 128, NULL);
  gint32 window_size = htonl (100);
  guint8 window_size_buf[4];
  memcpy(&window_size_buf[0], &window_size, sizeof (window_size));
  GByteArray * buf = g_byte_array_new ();
  g_byte_array_append (
    buf,
    window_size_buf,
    sizeof (window_size_buf));
  RTMP_Message message = {
    .fmt = 0,
    .type = MSG_WINDOW_ACK_SIZE,
    .len = 4,
    .timestamp = 0,
    .abs_timestamp = 0,
    .msg_stream_id = 0,
    .buf = buf
  };

  client_handle_message(client, &message);
  fail_unless_equals_int(client->window_size, 100);
  fail_unless (!client_window_size_reached (client));
  client->bytes_received_since_ack = 100;
  fail_unless (client_window_size_reached (client));
  g_byte_array_free(buf, TRUE);
  connections_free(connections);
  client_free(client);
  pex_rtmp_server_stop (server);
  pex_rtmp_server_free(server);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_notifications)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  /* don't allow any publishers in yet */
  h->reject_publishers = TRUE;

  /* try to add a publisher and a subscriber */
  gint abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_send_audio (h, abe, 1, 1);

  gint bob = rtmp_harness_add_subscriber (h, "test");

  /* verify the publisher is not connected, and the subscriber is */
  rtmp_harness_wait_for_notified_publishers (h, 0);
  rtmp_harness_wait_for_notified_subscribers (h, 1);
  fail_unless_equals_int (0, h->notified_publishers);
  fail_unless_equals_int (1, h->notified_subscribers);

  /* remove the subscriber */
  rtmp_harness_remove_subscriber (h, bob);
  fail_unless_equals_int (0, h->notified_subscribers);

  /* change to no allowing any subscribers in */
  h->reject_publishers = FALSE;
  h->reject_subscribers = TRUE;

  /* try to add another publisher and a subscriber */
  abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_send_audio (h, abe, 1, 1);

  gint bob2 = rtmp_harness_add_subscriber (h, "test");

  /* verify the subscriber is not connected, and the publisher is */
  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_wait_for_notified_subscribers (h, 0);
  fail_unless_equals_int (1, h->notified_publishers);
  fail_unless_equals_int (0, h->notified_subscribers);

  /* remove the publisher */
  rtmp_harness_remove_publisher (h, abe);
  fail_unless_equals_int (0, h->notified_publishers);

  /* allow subscribers in again */
  h->reject_subscribers = FALSE;
  bob2 = rtmp_harness_add_subscriber (h, "test");
  rtmp_harness_add_audiosink (h, bob2, RTMP_SPEEX);

  /* add a new publisher */
  abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);

  /* verfy media through */
  rtmp_harness_send_audio (h, abe, 7, 7);
  rtmp_harness_recv_audio (h, bob2, 6);
  fail_unless (rtmp_harness_verify_recv_audio (h, bob2, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_url_parse)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gchar * protocol = NULL;
  gint port;
  gchar * ip = NULL;
  gchar * application_name = NULL;
  gchar * path = NULL;

  /* ipv4 */
  fail_unless (pex_rtmp_server_parse_url (h->server,
     "rtmp://10.47.4.114:666/this/actually/works live=1",
      &protocol, &port, &ip, &application_name, &path));
  fail_unless (g_strcmp0 (protocol, "rtmp") == 0);
  fail_unless (g_strcmp0 (ip, "10.47.4.114") == 0);
  fail_unless_equals_int (port, 666);
  fail_unless (g_strcmp0 (application_name, "this/actually") == 0);
  fail_unless (g_strcmp0 (path, "works") == 0);

  g_free (protocol);
  g_free (ip);
  g_free (application_name);
  g_free (path);

  /* ipv4 no port - should default to 1935 */
  fail_unless (pex_rtmp_server_parse_url (h->server,
     "rtmp://10.47.4.114/this/actually/works",
      &protocol, &port, &ip, &application_name, &path));
  fail_unless (g_strcmp0 (protocol, "rtmp") == 0);
  fail_unless (g_strcmp0 (ip, "10.47.4.114") == 0);
  fail_unless_equals_int (port, 1935);
  fail_unless (g_strcmp0 (application_name, "this/actually") == 0);
  fail_unless (g_strcmp0 (path, "works") == 0);

  g_free (protocol);
  g_free (ip);
  g_free (application_name);
  g_free (path);

  /* ipv6 */
  fail_unless (pex_rtmp_server_parse_url (h->server,
     "rtmp://[2001:db8:0:1]:456/this/actually/works live=1",
      &protocol, &port, &ip, &application_name, &path));
  fail_unless (g_strcmp0 (protocol, "rtmp") == 0);
  fail_unless (g_strcmp0 (ip, "2001:db8:0:1") == 0);
  fail_unless_equals_int (port, 456);
  fail_unless (g_strcmp0 (application_name, "this/actually") == 0);
  fail_unless (g_strcmp0 (path, "works") == 0);

  g_free (protocol);
  g_free (ip);
  g_free (application_name);
  g_free (path);

  /* ipv6 no port - should default to 1935 */
  fail_unless (pex_rtmp_server_parse_url (h->server,
     "rtmp://FE80:0000:0000:0000:0202:B3FF:FE1E:8329/this/actually/works",
      &protocol, &port, &ip, &application_name, &path));
  fail_unless (g_strcmp0 (protocol, "rtmp") == 0);
  fail_unless (g_strcmp0 (ip, "FE80:0000:0000:0000:0202:B3FF:FE1E:8329") == 0);
  fail_unless_equals_int (port, 1935);
  fail_unless (g_strcmp0 (application_name, "this/actually") == 0);
  fail_unless (g_strcmp0 (path, "works") == 0);

  g_free (protocol);
  g_free (ip);
  g_free (application_name);
  g_free (path);

  /* rtmpx - should fail */
  fail_unless (!pex_rtmp_server_parse_url (h->server,
     "rtmpx://10.47.4.114:666/this/actually/works",
      &protocol, &port, &ip, &application_name, &path));

  /* no path - should fail */
  fail_unless (!pex_rtmp_server_parse_url (h->server,
     "rtmp://10.47.4.114:666/this",
      &protocol, &port, &ip, &application_name, &path));

  /* bogus - should fail */
  fail_unless (!pex_rtmp_server_parse_url (h->server,
     "This is bullshit!",
      &protocol, &port, &ip, &application_name, &path));

  /* missing "/" - should fail */
  fail_unless (!pex_rtmp_server_parse_url (h->server,
     "rtmp:/10.47.4.114:666/this/actually/works",
      &protocol, &port, &ip, &application_name, &path));

  /* missing port - should fail */
  fail_unless (!pex_rtmp_server_parse_url (h->server,
     "rtmp://10.47.4.114:/this/actually/works",
      &protocol, &port, &ip, &application_name, &path));


  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialin)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialin (h_bob, bob, h_abe, abe, "rtmp", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 3);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialin_and_dialout)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe_publisher = rtmp_harness_add_publisher (h_abe, "abe_publisher");
  gint abe_subscriber = rtmp_harness_add_subscriber (h_abe, "abe_subscriber");
  gint bob_publisher = rtmp_harness_add_publisher (h_bob, "bob_publisher");
  gint bob_subscriber = rtmp_harness_add_subscriber (h_bob, "bob_subscriber");

  rtmp_harness_add_audiosrc (h_abe, abe_publisher, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe_publisher);

  rtmp_harness_add_audiosink (h_abe, abe_subscriber, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_abe, abe_subscriber);

  rtmp_harness_add_audiosrc (h_bob, bob_publisher, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_bob, bob_publisher);

  rtmp_harness_add_audiosink (h_bob, bob_subscriber, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob_subscriber);

  rtmp_harness_dialout (h_bob, bob_subscriber, h_abe, abe_publisher, "rtmp", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_dialin (h_bob, bob_publisher, h_abe, abe_subscriber, "rtmp", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_send_audio_async (h_abe, abe_publisher, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe_publisher, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob_subscriber, 7);
  rtmp_harness_recv_video (h_bob, bob_subscriber, 3);

  rtmp_harness_send_audio_async (h_bob, bob_publisher, 6, 8);
  rtmp_harness_send_video_async (h_bob, bob_publisher, 5, 4);

  rtmp_harness_recv_audio (h_abe, abe_subscriber, 7);
  rtmp_harness_recv_video (h_abe, abe_subscriber, 3);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob_subscriber, abe_publisher));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob_subscriber, abe_publisher));
  fail_unless (rtmp_harness_verify_recv_audio (h_abe, abe_subscriber, bob_publisher));
  fail_unless (rtmp_harness_verify_recv_video (h_abe, abe_subscriber, bob_publisher));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialin_and_dialout_aac)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe_publisher = rtmp_harness_add_publisher (h_abe, "abe_publisher");
  gint abe_subscriber = rtmp_harness_add_subscriber (h_abe, "abe_subscriber");
  gint bob_publisher = rtmp_harness_add_publisher (h_bob, "bob_publisher");
  gint bob_subscriber = rtmp_harness_add_subscriber (h_bob, "bob_subscriber");

  rtmp_harness_add_audiosrc (h_abe, abe_publisher, RTMP_AAC);

  rtmp_harness_add_audiosink (h_abe, abe_subscriber, RTMP_AAC);

  rtmp_harness_add_audiosrc (h_bob, bob_publisher, RTMP_AAC);

  rtmp_harness_add_audiosink (h_bob, bob_subscriber, RTMP_AAC);

  rtmp_harness_dialout (h_bob, bob_subscriber, h_abe, abe_publisher, "rtmp", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);
  rtmp_harness_dialin (h_bob, bob_publisher, h_abe, abe_subscriber, "rtmp", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_bob, 1);

  rtmp_harness_send_audio (h_abe, abe_publisher, 20, 9);
  rtmp_harness_recv_audio (h_bob, bob_subscriber, 7);

  rtmp_harness_send_audio (h_bob, bob_publisher, 20, 9);
  rtmp_harness_recv_audio (h_abe, abe_subscriber, 7);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob_subscriber, abe_publisher));
  fail_unless (rtmp_harness_verify_recv_audio (h_abe, abe_subscriber, bob_publisher));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 3);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_close_tcp)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 3);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_remove_publisher(h_abe, abe);

  rtmp_harness_wait_for_notified_publishers (h_abe, 0);
  rtmp_harness_wait_for_notified_subscribers (h_abe, 0);

  rtmp_harness_wait_for_notified_publishers (h_bob, 0);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;


GST_START_TEST(rtmp_server_dialout_ipv6)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "::1", "::1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_dead_host_bug_4130)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);
  rtmp_harness_set_tcp_syncnt (h_abe, 1);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmp", "10.255.255.254", "10.255.255.254");
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_ssl_cn_dns)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_cn_dns.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_ssl_san_dns)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_san.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_ssl_cn_ip)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_cn_ip.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_ssl_san_ip)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_san.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, 1);

  rtmp_harness_send_audio_async (h_abe, abe, 6, 8);
  rtmp_harness_send_video_async (h_abe, abe, 5, 4);

  rtmp_harness_recv_audio (h_bob, bob, 7);
  rtmp_harness_recv_video (h_bob, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h_bob, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h_bob, bob, abe));

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_ssl_san_mismatch)
{
  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  RTMPHarness * h_bob = rtmp_harness_new_with_certs ("bob_live/is/also",
      "cert_san_mismatch.pem", "cert.key", "ca.pem");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);
  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, -2);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_dialout_ssl_no_trust)
{
  RTMPHarness * h_abe = rtmp_harness_new_with_certs ("abe_live/is/cool",
      "cert_san.pem", "cert.key", "ca-missing.pem");
  RTMPHarness * h_bob = rtmp_harness_new ("bob_live/is/also");
  rtmp_harness_set_chunk_size (h_abe, 17); /* crazy, yes, but proves we rock! */
  rtmp_harness_set_chunk_size (h_bob, 19);
  rtmp_harness_set_stream_id (h_abe, 1234567);
  rtmp_harness_set_stream_id (h_bob, 7654321);

  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  gint bob = rtmp_harness_add_subscriber (h_bob, "bob");

  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h_abe, abe);

  rtmp_harness_add_audiosink (h_bob, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h_bob, bob);

  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "localhost", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, -1);
  rtmp_harness_dialout (h_abe, abe, h_bob, bob, "rtmps", "127.0.0.1", "127.0.0.1");
  rtmp_harness_wait_for_notified_subscribers (h_abe, -2);

  rtmp_harness_teardown (h_abe);
  rtmp_harness_teardown (h_bob);
}
GST_END_TEST;

GST_START_TEST(rtmp_chunk_size_tiny)
{
  RTMPHarness * h = rtmp_harness_new ("live");
  rtmp_harness_set_chunk_size (h, 16);

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);

  rtmp_harness_send_audio (h, abe, 6, 8);
  rtmp_harness_recv_audio (h, bob, 7);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_extended_timestamp)
{
  RTMPHarness * h = rtmp_harness_new ("live");
  rtmp_harness_set_chunk_size (h, 16);

  gint abe = rtmp_harness_add_publisher (h, "test");
  gint bob = rtmp_harness_add_subscriber (h, "test");

  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_add_videosrc (h, abe);

  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);
  rtmp_harness_add_videosink (h, bob);

  rtmp_harness_send_audio_async (h, abe, 6, 8);
  rtmp_harness_send_video_async (h, abe, 5, 4);

  rtmp_harness_recv_audio (h, bob, 7);
  rtmp_harness_recv_video (h, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  /* jump time to the point where extended timestamps starts */
  rtmp_harness_set_timestamp_offset (h, 0xffffff * GST_MSECOND);

  /* get an intra frame */
  rtmp_harness_request_intra (h, abe);

  /* verify we can still send and receive just fine */
  rtmp_harness_send_audio_async (h, abe, 7, 7);
  rtmp_harness_send_video_async (h, abe, 4, 4);

  rtmp_harness_recv_audio (h, bob, 7);
  rtmp_harness_recv_video (h, bob, 4);

  fail_unless (rtmp_harness_verify_recv_audio (h, bob, abe));
  fail_unless (rtmp_harness_verify_recv_video (h, bob, abe));

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_nonblocking_handshake)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint fd = rtmp_harness_add_bad_client (h);

  rtmp_harness_teardown (h);
  close (fd);
}
GST_END_TEST;

GST_START_TEST(rtmp_nonblocking_outgoing_handshake)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  gint fd = rtmp_harness_add_bad_server (h, 2000);

  pex_rtmp_server_dialout (
      h->server, "streamname0", "rtmp://localhost:2000/app/streamname1",
      "127.0.0.1");

  rtmp_harness_teardown (h);
  close (fd);
}
GST_END_TEST;

GST_START_TEST(rtmp_server_stress_bug_4648)
{

  RTMPHarness * h_abe = rtmp_harness_new ("abe_live/is/cool");
  gint abe = rtmp_harness_add_publisher (h_abe, "abe");
  rtmp_harness_add_audiosrc (h_abe, abe, RTMP_SPEEX);

  const gint HARNESSES = 10;
  RTMPHarness * h_bob[HARNESSES];

  for (gint i = 0; i < HARNESSES; i++) {

    h_bob[i] = rtmp_harness_new_with_ports ("bob_live/is/also", 20000 + i, 30001 + i);
    gchar * path = g_strdup_printf ("bob_%d", i);
    gint bob = rtmp_harness_add_subscriber (h_bob[i], path);
    g_free (path);

    rtmp_harness_lock (h_abe);
    rtmp_harness_dialout (h_abe, abe, h_bob[i], bob, "rtmp", "127.0.0.1", "127.0.0.1");
    rtmp_harness_unlock (h_abe);
    rtmp_harness_send_audio (h_abe, abe, 8, 8);
  }

  rtmp_harness_teardown (h_abe);

 for (gint i = 0; i < HARNESSES; i++) {
    rtmp_harness_teardown (h_bob[i]);
  }

}
GST_END_TEST;

GST_START_TEST(rtmp_unlock_sink_bug5054)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  h->block_on_publish = TRUE;

  gint abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_send_audio_async (h, abe, 7, 7);

  rtmp_harness_wait_for_notified_publishers (h, 1);
  rtmp_harness_remove_publisher (h, abe);
  h->block_on_publish = FALSE;

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmp_unlock_src)
{
  RTMPHarness * h = rtmp_harness_new ("live");

  h->block_on_play = TRUE;

  gint abe = rtmp_harness_add_publisher (h, "test");
  rtmp_harness_add_audiosrc (h, abe, RTMP_SPEEX);
  rtmp_harness_send_audio (h, abe, 7, 7);
  rtmp_harness_wait_for_notified_publishers (h, 1);

  gint bob = rtmp_harness_add_subscriber (h, "test");
  rtmp_harness_add_audiosink (h, bob, RTMP_SPEEX);
  rtmp_harness_wait_for_notified_subscribers (h, 1);

  rtmp_harness_wait_for_rtmpsrc_connection (h, bob, TRUE);

  rtmp_harness_remove_subscriber (h, bob);
  h->block_on_play = FALSE;

  rtmp_harness_teardown (h);
}
GST_END_TEST;

GST_START_TEST(rtmpsink_start_stop_start)
{
  GstHarness * h = gst_harness_new_parse ("rtmpsink location=rtmp://foo/bar/baz");
  GstElement * sink = h->element;
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

static Suite *
rtmp_suite (void)
{
  Suite * s = suite_create ("rtmp");

  TCase * tc_chain = tcase_create ("general");
  tcase_add_checked_fixture (tc_chain, rtmp_setup, rtmp_teardown);
  suite_add_tcase (s, tc_chain);

  tcase_add_test (tc_chain, rtmp_speex_flv_end_to_end);

  tcase_add_test (tc_chain, rtmp_flv_timestamping_basics);
  tcase_add_test (tc_chain, rtmp_flv_timestamping_into_running_pipeline);
  tcase_add_test (tc_chain, rtmp_flv_timestamping_from_running_pipeline);
  tcase_add_test (tc_chain, rtmp_flv_timestamping_with_gap);
  tcase_add_test (tc_chain, rtmp_flv_aac);

  tcase_add_test (tc_chain, rtmp_audio_speex);
  tcase_add_test (tc_chain, rtmp_audio_aac);
  tcase_add_test (tc_chain, rtmp_video);
  tcase_add_test (tc_chain, rtmp_audio_and_video);
  tcase_add_test (tc_chain, rtmp_audio_and_video_ssl);
  tcase_add_test (tc_chain, rtmp_audio_and_video_rtmps_to_rtmp);
  tcase_add_test (tc_chain, rtmp_audio_and_video_rtmp_to_rtmps);
  tcase_add_test (tc_chain, rtmp_one_publisher_n_subscribers);
  tcase_add_test (tc_chain, rtmp_multiple_paths);
  tcase_add_test (tc_chain, rtmp_audio_automatic_reconnect);
  tcase_add_test (tc_chain, rtmp_flash_handshake);

  tcase_add_test (tc_chain, rtmp_amf3_object_parsing);
  tcase_add_test (tc_chain, rtmp_amf3_coverity_add_int);
  tcase_add_test (tc_chain, rtmp_amf0_object_parsing);
  tcase_add_test (tc_chain, rtmp_amf0_object_parsing_wowza_connect);
  tcase_add_test (tc_chain, rtmp_amf0_ecma_array_parsing);
  tcase_add_test (tc_chain, rtmp_amf_issue_4512);
  tcase_add_test (tc_chain, rtmp_amf_dec_fuzzing);

  tcase_add_test (tc_chain, rtmp_window_size);
  (void)rtmp_server_notifications;
  //tcase_add_test (tc_chain, rtmp_server_notifications);

  tcase_add_test (tc_chain, rtmp_server_url_parse);
  tcase_add_test (tc_chain, rtmp_server_dialin);
  tcase_add_test (tc_chain, rtmp_server_dialin_and_dialout);
  tcase_add_test (tc_chain, rtmp_server_dialin_and_dialout_aac);
  tcase_add_test (tc_chain, rtmp_server_dialout);
  tcase_add_test (tc_chain, rtmp_server_dialout_close_tcp);
  tcase_add_test (tc_chain, rtmp_server_dialout_ipv6);

#ifdef __APPLE__
  (void) rtmp_server_dialout_dead_host_bug_4130;
#else
  tcase_add_test (tc_chain, rtmp_server_dialout_dead_host_bug_4130);
#endif
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_cn_dns);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_san_dns);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_cn_ip);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_san_ip);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_san_mismatch);
  tcase_add_test (tc_chain, rtmp_server_dialout_ssl_no_trust);

  tcase_add_test (tc_chain, rtmp_chunk_size_tiny);
  tcase_add_test (tc_chain, rtmp_extended_timestamp);
  tcase_add_test (tc_chain, rtmp_nonblocking_handshake);
  tcase_add_test (tc_chain, rtmp_nonblocking_outgoing_handshake);
  tcase_add_test (tc_chain, rtmp_server_stress_bug_4648);

  tcase_add_test (tc_chain, rtmp_unlock_sink_bug5054);
  tcase_add_test (tc_chain, rtmp_unlock_src);
  tcase_add_test (tc_chain, rtmpsink_start_stop_start);
  return s;
}

PEX_CHECK_MAIN (rtmp)
