/* PexRTMPServer
 *
 * Regression tests for a set of security findings:
 *   - RTMP subscriber-list use-after-free (connections.c)
 *   - RTMP AMF unbounded recursion DoS (amf.c)
 *   - RTMP user-control / control-message out-of-bounds heap reads (client.c)
 *
 * These tests are intentionally self-contained and only rely on glib/gst and
 * the public PexRTMPServer APIs so that they can be built and run as part of
 * the meson `check` target.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gst/gst.h>
#include <string.h>

#include "connections.h"
#include "client.h"
#include "rtmp.h"
#include "utils/amf.h"

/*
 * Finding #3 — RTMP Subscriber-List Use-After-Free
 *
 * A client that sends play() twice used to be appended to the subscriber list
 * twice (g_slist_append with no dedup). On teardown only the first entry was
 * removed (g_slist_remove), leaving a dangling pointer behind.
 */
static void
test_subscriber_no_duplicate (void)
{
  Connections *connections = connections_new ();
  gint client_a = 0xA;          /* used purely as a unique pointer value */
  const gchar *path = "/live/stream";

  /* simulate a client sending play() twice */
  connections_add_subscriber (connections, &client_a, path);
  connections_add_subscriber (connections, &client_a, path);

  GSList *subscribers = connections_get_subscribers (connections, path);
  g_assert_cmpuint (g_slist_length (subscribers), ==, 1);

  /* a single teardown must leave no dangling reference behind */
  connections_remove_client (connections, &client_a, path);
  subscribers = connections_get_subscribers (connections, path);
  g_assert_cmpuint (g_slist_length (subscribers), ==, 0);

  connections_free (connections);
}

static void
test_subscriber_remove_all (void)
{
  Connections *connections = connections_new ();
  gint client_a = 0xA;
  gint client_b = 0xB;
  const gchar *path = "/live/stream";

  connections_add_subscriber (connections, &client_a, path);
  connections_add_subscriber (connections, &client_b, path);
  g_assert_cmpuint (g_slist_length (connections_get_subscribers (connections,
              path)), ==, 2);

  /* removing one client must not affect the other */
  connections_remove_client (connections, &client_a, path);
  GSList *subscribers = connections_get_subscribers (connections, path);
  g_assert_cmpuint (g_slist_length (subscribers), ==, 1);
  g_assert (subscribers->data == &client_b);

  connections_remove_client (connections, &client_b, path);
  g_assert_cmpuint (g_slist_length (connections_get_subscribers (connections,
              path)), ==, 0);

  connections_free (connections);
}

/*
 * Finding #6 — RTMP AMF Unbounded Recursion DoS
 *
 * Build a deeply nested AMF0 object and make sure decoding it terminates
 * without exhausting the C stack.
 */
static GByteArray *
build_nested_amf0_object (guint depth)
{
  GByteArray *buf = g_byte_array_new ();
  const guint8 object_marker = AMF0_OBJECT;
  const guint8 key[] = { 0x00, 0x01, 'a' };     /* 16-bit length + 'a' */
  const guint8 object_end[] = { 0x00, 0x00, AMF0_OBJECT_END };

  /* opening: depth nested objects, each with a single key "a" */
  for (guint i = 0; i < depth; i++) {
    g_byte_array_append (buf, &object_marker, 1);
    g_byte_array_append (buf, key, sizeof (key));
  }

  /* innermost empty object */
  g_byte_array_append (buf, &object_marker, 1);
  g_byte_array_append (buf, object_end, sizeof (object_end));

  /* closing object-end markers for each wrapping object */
  for (guint i = 0; i < depth; i++)
    g_byte_array_append (buf, object_end, sizeof (object_end));

  return buf;
}

static void
test_amf_deep_recursion (void)
{
  /* A depth this large would blow the stack with the old unbounded
   * mutual recursion. With the depth limit it must return safely. */
  GByteArray *buf = build_nested_amf0_object (200000);
  AmfDec *dec = amf_dec_new (buf, 0);

  GstStructure *object = amf_dec_load_object (dec);
  g_assert (object != NULL);
  gst_structure_free (object);

  amf_dec_free (dec);
  g_byte_array_free (buf, TRUE);
}

/*
 * Finding #11 (and adjacent control messages) — out-of-bounds heap reads.
 *
 * client_handle_message() used to read a 16-bit method and a 32-bit timestamp
 * from a MSG_USER_CONTROL payload without checking the buffer length. Similar
 * unchecked reads existed for MSG_WINDOW_ACK_SIZE, MSG_SET_PEER_BW, MSG_AUDIO
 * and MSG_VIDEO. A short payload must now be rejected instead of read OOB.
 */
static Client *
make_test_client (Connections * connections)
{
  return client_new (NULL, 0, connections, 0, DEFAULT_CHUNK_SIZE, NULL);
}

static PexRtmpServerStatus
handle_short_message (Client * client, guint8 type, const guint8 * data,
    guint len)
{
  RTMPMessage msg;
  memset (&msg, 0, sizeof (msg));
  msg.type = type;
  msg.buf = g_byte_array_new ();
  if (len > 0)
    g_byte_array_append (msg.buf, data, len);
  msg.len = len;

  PexRtmpServerStatus ret = client_handle_message (client, &msg);
  g_byte_array_free (msg.buf, TRUE);
  return ret;
}

static void
test_user_control_oob_read (void)
{
  Connections *connections = connections_new ();
  Client *client = make_test_client (connections);

  /* method == 6 (SetBufferLength) but no room for the 32-bit timestamp */
  const guint8 short_payload[] = { 0x00, 0x06 };
  PexRtmpServerStatus ret = handle_short_message (client, MSG_USER_CONTROL,
      short_payload, sizeof (short_payload));
  g_assert_cmpint (ret, ==, PEX_RTMP_SERVER_STATUS_INVALID_MSG);

  /* empty payload: not even the method fits */
  ret = handle_short_message (client, MSG_USER_CONTROL, NULL, 0);
  g_assert_cmpint (ret, ==, PEX_RTMP_SERVER_STATUS_INVALID_MSG);

  client_unref (client);
  connections_free (connections);
}

static void
test_control_msg_oob_read (void)
{
  Connections *connections = connections_new ();
  Client *client = make_test_client (connections);

  const guint8 two_bytes[] = { 0x00, 0x01 };

  g_assert_cmpint (handle_short_message (client, MSG_WINDOW_ACK_SIZE,
          two_bytes, sizeof (two_bytes)), ==,
      PEX_RTMP_SERVER_STATUS_INVALID_MSG);

  g_assert_cmpint (handle_short_message (client, MSG_SET_PEER_BW,
          two_bytes, sizeof (two_bytes)), ==,
      PEX_RTMP_SERVER_STATUS_INVALID_MSG);

  client_unref (client);
  connections_free (connections);
}

static void
test_av_msg_oob_read (void)
{
  Connections *connections = connections_new ();
  Client *client = make_test_client (connections);

  /* Mark the client as a publisher so we reach the payload-reading code. */
  client_configure_direct (client, "/live/stream", TRUE);

  /* zero-length audio/video payloads must not read data[0]/data[1] OOB */
  g_assert_cmpint (handle_short_message (client, MSG_AUDIO, NULL, 0), ==,
      PEX_RTMP_SERVER_STATUS_INVALID_MSG);
  g_assert_cmpint (handle_short_message (client, MSG_VIDEO, NULL, 0), ==,
      PEX_RTMP_SERVER_STATUS_INVALID_MSG);

  client_unref (client);
  connections_free (connections);
}

int
main (int argc, char **argv)
{
  gst_init (&argc, &argv);
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/security/subscriber-no-duplicate",
      test_subscriber_no_duplicate);
  g_test_add_func ("/security/subscriber-remove-all",
      test_subscriber_remove_all);
  g_test_add_func ("/security/amf-deep-recursion", test_amf_deep_recursion);
  g_test_add_func ("/security/user-control-oob-read",
      test_user_control_oob_read);
  g_test_add_func ("/security/control-msg-oob-read", test_control_msg_oob_read);
  g_test_add_func ("/security/av-msg-oob-read", test_av_msg_oob_read);

  return g_test_run ();
}
