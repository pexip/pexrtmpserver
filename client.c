/*
 * RTMPServer
 *
 * Copyright 2011 Janne Kulmala <janne.t.kulmala@iki.fi>
 * Copyright 2014 Pexip         <pexip.com>
 *
 * Program code is licensed with GNU LGPL 2.1. See COPYING.LGPL file.
 */

#include "client.h"

#include "amf.h"
#include "utils.h"
#include "rtmp.h"

#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug


static void
client_write_extended_timestamp (Client * client, guint32 timestamp)
{
  guint32 ext_timestamp = GUINT32_FROM_BE (timestamp);
  client->send_queue = g_byte_array_append (client->send_queue,
      (guint8 *)&ext_timestamp, 4);
  client->written_seq += 4;
}

static void
client_rtmp_send (Client * client, guint8 msg_type_id, guint32 msg_stream_id,
    GByteArray * buf, guint32 abs_timestamp, guint8 chunk_stream_id)
{
  gint fmt = 0;
  guint32 timestamp = abs_timestamp;
  const guint msg_len = buf->len;
  gint use_ext_timestamp = timestamp >= EXT_TIMESTAMP_LIMIT;

#if 0 /* FIXME: disable pending investigation on why YouTube fails */
  /* type 1 check */
  if (msg_stream_id != MSG_STREAM_ID_CONTROL &&
      client->prev_header.msg_stream_id == msg_stream_id) {
    fmt = 1;
    /* calculate timestamp delta */
    timestamp = abs_timestamp - client->prev_header.abs_timestamp;

    /* type 2 check */
    if (client->prev_header.msg_len == msg_len &&
        client->prev_header.msg_type_id == msg_type_id) {
      fmt = 2;

      /* type 3 check */
      if (client->prev_header.timestamp == timestamp)
        fmt = 3;
    }
  }
#endif

  /* store relevant header-data */
  client->prev_header.timestamp = timestamp;
  client->prev_header.msg_stream_id = msg_stream_id;
  client->prev_header.abs_timestamp = abs_timestamp;
  client->prev_header.msg_len = msg_len;
  client->prev_header.msg_type_id = msg_type_id;

  RTMP_Header header;
  guint header_len = CHUNK_MSG_HEADER_LENGTH[fmt];
  chunk_stream_id &= 0x3f;
  header.flags = chunk_stream_id | (fmt << 6);
  header.msg_type_id = msg_type_id;
  if (use_ext_timestamp) {
    set_be24 (header.timestamp, EXT_TIMESTAMP_LIMIT);
  } else {
    set_be24 (header.timestamp, timestamp);
  }
  set_be24 (header.msg_len, msg_len);
  header.msg_stream_id = msg_stream_id;
  GST_LOG_OBJECT (client->server, "Sending packet with:\n"
      "format:%d, chunk_stream_id:%u, timestamp:%u, msg_len:%u, msg_type_id:%u, msg_stream_id:%u",
      fmt, chunk_stream_id, timestamp, msg_len, msg_type_id, msg_stream_id);
  client->send_queue = g_byte_array_append (client->send_queue,
      (guint8 *)&header, header_len);
  client->written_seq += header_len;

  if (use_ext_timestamp)
    client_write_extended_timestamp (client, timestamp);

  guint pos = 0;
  while (pos < msg_len) {
    if (pos) {
      guint8 flags = chunk_stream_id | (3 << 6);
      client->send_queue = g_byte_array_append (client->send_queue, &flags, 1);
      client->written_seq += 1;

      /* we rewrite the extended timestamp for multiple chunks in a message, like Flash does */
      if (use_ext_timestamp)
        client_write_extended_timestamp (client, timestamp);
    }

    guint chunk = msg_len - pos;
    if (chunk > client->send_chunk_size)
      chunk = client->send_chunk_size;
    client->send_queue = g_byte_array_append (client->send_queue,
        &buf->data[pos], chunk);

    client_try_to_send (client, NULL);

    client->written_seq += chunk;
    pos += chunk;

    GST_LOG_OBJECT (client->server, "Sent chunk of size %u (%u / %u)",
        chunk, pos, msg_len);
  }

}

static void
client_send_reply (Client * client, double txid, const GValue * reply,
    const GValue * status)
{
  if (txid <= 0.0)
    return;

  AmfEnc * invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "_result");
  amf_enc_write_double (invoke, txid);
  amf_enc_write_value (invoke, reply);
  amf_enc_write_value (invoke, status);

  client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
  amf_enc_free (invoke);
}

/* Result messages come from a server to the client,
   but in the dial-out case we are both! */
static void
client_handle_subscribe_result (Client *client, gint txid, AmfDec * dec)
{
  if (txid == 1) {
    GST_DEBUG_OBJECT (client->server, "Sending releaseStream + FCPublish + createStream");
    AmfEnc * invoke;
    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "releaseStream");
    amf_enc_write_double (invoke, 2.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);

    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "FCPublish");
    amf_enc_write_double (invoke, 3.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);

    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "createStream");
    amf_enc_write_double (invoke, 4.0);
    amf_enc_write_null (invoke);
    client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);
  } else if (txid == 4) {
    GValue * reply = amf_dec_load (dec);
    GValue * status = amf_dec_load (dec);
    client->msg_stream_id = (guint)g_value_get_double(status);
    GST_DEBUG_OBJECT (client->server, "Got message stream id %d", client->msg_stream_id);
    g_value_unset (reply);
    g_value_unset (status);
    g_free (reply);
    g_free (status);

    GST_DEBUG_OBJECT (client->server, "Sending publish to %s", client->dialout_path);
    AmfEnc * invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "publish");
    amf_enc_write_double (invoke, 0.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    amf_enc_write_string (invoke, "live");
    client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    amf_enc_free (invoke);
  }
}

static void
client_handle_publish_result (Client *client, gint txid, AmfDec * dec)
{
  if (txid == 1) {
    GST_DEBUG_OBJECT (client->server, "Sending createStream");
    AmfEnc * invoke;
    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "createStream");
    amf_enc_write_double (invoke, 2.0);
    amf_enc_write_null (invoke);
    client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);
  } else if (txid == 2) {
    GValue * reply = amf_dec_load (dec);
    GValue * status = amf_dec_load (dec);
    client->msg_stream_id = (guint)g_value_get_double(status);
    GST_DEBUG_OBJECT (client->server, "Got message stream id %d", client->msg_stream_id);
    g_value_unset (reply);
    g_value_unset (status);
    g_free (reply);
    g_free (status);

    GST_DEBUG_OBJECT (client->server, "Sending play to %s", client->dialout_path);
    AmfEnc * invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "play");
    amf_enc_write_double (invoke, 0.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    amf_enc_free (invoke);
  }
}

static void
client_handle_result (Client * client, gint txid, AmfDec * dec)
{
  /* we won't handle this unless we are dialing out to a path */
  if (client->dialout_path == NULL)
    return;

  (void)dec;
  GST_DEBUG_OBJECT (client->server, "Handling result for txid %d", txid);
  if (!client->publisher) {
    client_handle_subscribe_result (client, txid, dec);
  } else {
    client_handle_publish_result (client, txid, dec);
  }
}

static gboolean
client_handle_onstatus (Client * client, double txid, AmfDec * dec, gint stream_id)
{
  (void)txid;
  /* we won't handle this unless we are dialing out to a path */
  if (client->dialout_path == NULL)
    return TRUE;

  g_free (amf_dec_load (dec));           /* NULL */
  GstStructure * object = amf_dec_load_object (dec);

  const gchar * code = gst_structure_get_string (object, "code");
  GST_DEBUG_OBJECT (client->server, "onStatus - code: %s", code);
  if (code && g_strcmp0 (code, "NetStream.Play.Start") == 0) {
    /* make the client a subscriber on the local server */
    connections_add_publisher (client->connections, client, client->path);
    gboolean reject_play = FALSE;
    g_signal_emit_by_name (client->server, "on-publish", client->path, &reject_play);
  }
  if (code && g_strcmp0 (code, "NetStream.Publish.Start") == 0) {
    /* make the client a subscriber on the local server */
    connections_add_subscriber (client->connections, client, client->path);

    GstStructure * meta = gst_structure_new ("object",
        "framerate", G_TYPE_DOUBLE, 30.0,
        "width", G_TYPE_DOUBLE, 1280.0,
        "height", G_TYPE_DOUBLE, 720.0,
        "videocodecid", G_TYPE_STRING, "avc1",
        "videodatarate", G_TYPE_DOUBLE, 2000.0,
        "avclevel", G_TYPE_DOUBLE, 31.0,
        "avcprofile", G_TYPE_DOUBLE, 66.0,
        "videokeyframe_frequency", G_TYPE_DOUBLE, 2.0,
        "audiosamplerate", G_TYPE_DOUBLE, 48000.0,
        "audiochannels", G_TYPE_DOUBLE, 1.0,
        "audiocodecid", G_TYPE_STRING, "mp4a",
        "audiodatarate", G_TYPE_DOUBLE, 64.0,
        NULL);
    AmfEnc * invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "@setDataFrame");
    amf_enc_write_string (invoke, "onMetaData");
    amf_enc_write_object (invoke, meta);
    client_rtmp_send (client, MSG_NOTIFY, stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    amf_enc_free (invoke);
    gst_structure_free (meta);
    gboolean reject_play = FALSE;
    g_signal_emit_by_name (client->server, "on-play", client->path, &reject_play);
  }


  gst_structure_free (object);
  return TRUE;
}

static void
client_set_chunk_size (Client * client, gint chunk_size)
{
  GST_DEBUG_OBJECT (client->server, "Setting new send-chunk-size to %d", chunk_size);

  AmfEnc * invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (chunk_size));
  client_rtmp_send(client, MSG_SET_CHUNK, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);
  client->send_chunk_size = chunk_size;
}

static void
client_do_connect (Client * client)
{
  GST_DEBUG_OBJECT (client->server, "connecting to: %s with path: %s",
      client->tcUrl, client->path);

  /* send connect */
  GstStructure * status = gst_structure_new ("object",
      "app", G_TYPE_STRING, client->app,
      "tcUrl", G_TYPE_STRING, client->tcUrl,
      "type", G_TYPE_STRING, "nonprivate",
      "fpad", G_TYPE_BOOLEAN, TRUE,
      "flashVer", G_TYPE_STRING, "Pexip RTMP Server",
      "swfUrl", G_TYPE_STRING, client->tcUrl,
      NULL);

//      "fpad", G_TYPE_BOOLEAN, TRUE, /* we are doing proxying */
//      "audioCodecs", G_TYPE_DOUBLE, (gdouble)(SUPPORT_SND_AAC | SUPPORT_SND_SPEEX),
//      "videoCodecs", G_TYPE_DOUBLE, (gdouble)SUPPORT_VID_H264,
//      "videoFunctions", G_TYPE_DOUBLE, 0.0, /* We can't do seek */
//      "objectEncoding", G_TYPE_DOUBLE, 0.0, /* AMF0 */

  AmfEnc * invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "connect");
  amf_enc_write_double (invoke, 1.0);
  amf_enc_write_object (invoke, status);

  client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
  amf_enc_free (invoke);
  gst_structure_free (status);

  client_set_chunk_size (client, client->chunk_size);
}

static void
client_handle_connect (Client * client, double txid, AmfDec * dec)
{
  AmfEnc * invoke;
  GstStructure * params = amf_dec_load_object (dec);

  /* FIXME: support multiple applications */
  //if (strcmp (app, application_name) != 0) {
  //  g_GST_WARNING_OBJECT (client->server, "Unsupported application: %s", app);
  //}

  client->app = g_strdup (gst_structure_get_string (params, "app"));
  gchar * params_str = gst_structure_to_string (params);
  GST_DEBUG_OBJECT (client->server, "connect: %s", params_str);
  g_free (params_str);
  gst_structure_free (params);

  /* Send win ack size */
  invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (client->window_size));
  client_rtmp_send (client, MSG_WINDOW_ACK_SIZE, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);

  /* Send set peer bandwidth */
  invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (5000000));
  amf_enc_add_char (invoke, AMF_DYNAMIC);
  client_rtmp_send (client, MSG_SET_PEER_BW, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);

  /* Set sending chunk size */
  client_set_chunk_size (client, client->chunk_size);

  GValue version = G_VALUE_INIT;
  g_value_init (&version, GST_TYPE_STRUCTURE);
  GstStructure * version_s = gst_structure_new ("object",
      "fmsVer", G_TYPE_STRING, "FMS/3,5,3,824",
      "capabilities", G_TYPE_DOUBLE, 127.0,
      "mode", G_TYPE_DOUBLE, 1.0,
      NULL);
  gst_value_set_structure (&version, version_s);
  gst_structure_free (version_s);

  GValue status = G_VALUE_INIT;
  g_value_init (&status, GST_TYPE_STRUCTURE);
  GstStructure * status_s = gst_structure_new ("object",
      "level", G_TYPE_STRING, "status",
      "code", G_TYPE_STRING, "NetConnection.Connect.Success",
      "description", G_TYPE_STRING, "Connection succeeded.",
      "objectEncoding", G_TYPE_DOUBLE, 0.0,
      NULL);
  gst_value_set_structure (&status, status_s);
  gst_structure_free (status_s);

  client_send_reply (client, txid, &version, &status);
  g_value_unset (&version);
  g_value_unset (&status);
}

static void
client_handle_fcpublish (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));           /* NULL */

  gchar * path = amf_dec_load_string (dec);
  GST_DEBUG_OBJECT (client->server, "fcpublish %s", path);

  GstStructure * status = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetStream.Publish.Start",
      "description", G_TYPE_STRING, path,
      NULL);
  g_free (path);

  AmfEnc * invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onFCPublish");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);
  gst_structure_free (status);

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);
}

static void
client_handle_createstream (Client * client, double txid)
{
  GValue null_value = G_VALUE_INIT;
  GValue stream_id = G_VALUE_INIT;
  g_value_init (&stream_id, G_TYPE_DOUBLE);
  g_value_set_double (&stream_id, (gdouble)client->msg_stream_id);
  client_send_reply (client, txid, &null_value, &stream_id);
}

static gboolean
client_handle_publish (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec)); /* NULL */
  gchar * path = amf_dec_load_string (dec);
  GST_DEBUG_OBJECT (client->server, "publish %s", path);

  client->publisher = TRUE;
  g_free (client->path);
  client->path = path;

  gboolean reject_publish = FALSE;
  g_signal_emit_by_name(client->server, "on-publish", path, &reject_publish);
  if (reject_publish) {
    GST_DEBUG_OBJECT (client->server, "Not publishing due to signal rejecting publish");
    return FALSE;
  }
  connections_add_publisher (client->connections, client, path);
  GST_DEBUG_OBJECT (client->server, "publisher connected.");

  /* StreamBegin */
  AmfEnc * control = amf_enc_new ();
  amf_enc_add_short (control, htons (CONTROL_CLEAR_STREAM));
  amf_enc_add_int (control, htonl (client->msg_stream_id));
  client_rtmp_send (client, MSG_USER_CONTROL, MSG_STREAM_ID_CONTROL,
                    control->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (control);

  /* _result for publish */
  GstStructure * status = gst_structure_new ("object",
      "level", G_TYPE_STRING, "status",
      "code", G_TYPE_STRING, "NetStream.Publish.Start",
      "description", G_TYPE_STRING, "Stream is now published.",
      "details", G_TYPE_STRING, path,
      NULL);
  AmfEnc * invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onStatus");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
  amf_enc_free (invoke);
  gst_structure_free (status);

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);

  return TRUE;
}

static void
client_start_playback (Client * client)
{
  /* StreamBegin */
  AmfEnc * control = amf_enc_new ();
  amf_enc_add_short (control, htons (CONTROL_CLEAR_STREAM));
  amf_enc_add_int (control, htonl (client->msg_stream_id));
  client_rtmp_send (client, MSG_USER_CONTROL, MSG_STREAM_ID_CONTROL,
                    control->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (control);

  GstStructure * status = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetStream.Play.Reset",
      "description", G_TYPE_STRING, "Resetting and playing stream.",
      "level", G_TYPE_STRING, "status",
      NULL);
  AmfEnc * invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onStatus");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);
  gst_structure_free (status);

  status = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetStream.Play.Start",
      "description", G_TYPE_STRING, "Started playing.",
      "level", G_TYPE_STRING, "status", NULL);
  invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onStatus");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);
  gst_structure_free (status);

  invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "|RtmpSampleAccess");
  amf_enc_write_bool (invoke, TRUE);
  amf_enc_write_bool (invoke, TRUE);

  client_rtmp_send (client, MSG_NOTIFY, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);

  client->playing = TRUE;
  client->ready = FALSE;

  connections_add_subscriber (client->connections, client, client->path);

  /* send pexip metadata to the client */
  GstStructure * metadata = gst_structure_new ("metadata",
      "Server", G_TYPE_STRING, "Pexip RTMP Server", NULL);
  GST_DEBUG_OBJECT (client->server, "(%s) METADATA %"GST_PTR_FORMAT,
      client->path, metadata);
  invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onMetaData");
  amf_enc_write_object (invoke, metadata);
  client_rtmp_send (client, MSG_NOTIFY, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);
  gst_structure_free (metadata);
}

static gboolean
client_handle_play (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));           /* NULL */

  gchar * path = amf_dec_load_string (dec);
  g_free (client->path);
  client->path = path;
  gboolean reject_play = FALSE;
  g_signal_emit_by_name(client->server, "on-play", path, &reject_play);
  if (reject_play) {
    GST_DEBUG_OBJECT (client->server, "%p Not playing due to signal returning 0", client);
    return FALSE;
  }
  GST_DEBUG_OBJECT (client->server, "client %p got play for path: %s", client, path);

  client_start_playback (client);

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);

  return TRUE;
}

static void
client_handle_play2 (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));           /* NULL */

  GstStructure * params = amf_dec_load_object (dec);
  const gchar * path = gst_structure_get_string (params, "streamName");
  GST_DEBUG_OBJECT (client->server, "play2 %s", path);
  gst_structure_free (params);

  client_start_playback (client);

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);
}

static void
client_handle_pause (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));           /* NULL */

  gboolean paused;
  if (amf_dec_load_boolean (dec, &paused) && paused) {
    GST_DEBUG_OBJECT (client->server, "pausing");

    GstStructure * status = gst_structure_new ("object",
        "code", G_TYPE_STRING, "NetStream.Pause.Notify",
        "description", G_TYPE_STRING, "Pausing.",
        "level", G_TYPE_STRING, "status",
        NULL);
    AmfEnc * invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "onStatus");
    amf_enc_write_double (invoke, 0.0);
    amf_enc_write_null (invoke);
    amf_enc_write_object (invoke, status);

    client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    client->playing = FALSE;
  } else {
    client_start_playback (client);
  }

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);
}

static void
client_handle_setdataframe (Client * client, AmfDec * dec)
{
  if (!client->publisher) {
    GST_WARNING_OBJECT (client->server, "not a publisher");
    return;
  }

  gchar * type = amf_dec_load_string (dec);
  if (strcmp (type, "onMetaData") != 0) {
    GST_WARNING_OBJECT (client->server, "can only set metadata");
  }
  g_free (type);

  if (client->metadata)
    gst_structure_free (client->metadata);
  client->metadata = amf_dec_load_object (dec);
  GST_DEBUG_OBJECT (client->server, "(%s) METADATA %"GST_PTR_FORMAT,
      client->path, client->metadata);
}

static gboolean
client_handle_user_control (Client * client, const guint32 timestamp)
{
  AmfEnc * enc= amf_enc_new ();
  guint16 ping_response_id = 7;
  amf_enc_add_short (enc, htons (ping_response_id));
  amf_enc_add_int (enc, htonl (timestamp));
  client_rtmp_send (client, MSG_USER_CONTROL, MSG_STREAM_ID_CONTROL,
      enc->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free(enc);
  return TRUE;
}

static gboolean
client_handle_invoke (Client * client, const RTMP_Message * msg, AmfDec * dec)
{
  gboolean ret = TRUE;
  gchar * method = amf_dec_load_string (dec);
  gdouble txid;
  if (!amf_dec_load_number (dec, &txid))
    return FALSE;

  GST_DEBUG_OBJECT (client->server, "%p: invoked %s with txid %lf for Stream Id: %d ",
      client, method, txid, msg->msg_stream_id);

  if (strcmp (method, "onStatus") == 0) {
    ret = client_handle_onstatus (client, txid, dec, msg->msg_stream_id);
  } else if (msg->msg_stream_id == MSG_STREAM_ID_CONTROL) {
    if (strcmp (method, "connect") == 0) {
      client_handle_connect (client, txid, dec);
    } else if (strcmp (method, "FCPublish") == 0) {
      client_handle_fcpublish (client, txid, dec);
    } else if (strcmp (method, "createStream") == 0) {
      client_handle_createstream (client, txid);
    } else if (strcmp (method, "_result") == 0) {
      client_handle_result (client, (gint)txid, dec);
    }
  } else if (msg->msg_stream_id == client->msg_stream_id) {
    if (strcmp (method, "publish") == 0) {
      ret = client_handle_publish (client, txid, dec);
    } else if (strcmp (method, "play") == 0) {
      ret = client_handle_play (client, txid, dec);
    } else if (strcmp (method, "play2") == 0) {
      client_handle_play2 (client, txid, dec);
    } else if (strcmp (method, "pause") == 0) {
      client_handle_pause (client, txid, dec);
    }
  }

  g_free (method);
  return ret;
}

gboolean
client_window_size_reached (Client *client)
{
  return (client->bytes_received_since_ack >= client->window_size);
}

static void
client_send_ack (Client *client)
{
  AmfEnc * enc= amf_enc_new ();
  amf_enc_add_int (enc, htonl (client->total_bytes_received));
  client->bytes_received_since_ack = 0;
  client_rtmp_send(client, MSG_ACK, MSG_STREAM_ID_CONTROL,
      enc->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free(enc);
}

gboolean
client_handle_message (Client * client, RTMP_Message * msg)
{
  GST_LOG_OBJECT (client->server, "RTMP message %02x, len %u, abs-timestamp %u",
      msg->type, msg->len, msg->abs_timestamp);
  gboolean ret = TRUE;

  /* send window-size ACK if we have reached it */
  client->total_bytes_received += msg->len;
  if (client->publisher) {
    client->bytes_received_since_ack += msg->len;
    if (client_window_size_reached (client))
      client_send_ack (client);
  }

  guint pos = 0;
  switch (msg->type) {
    case MSG_ACK:
      if (pos + 4 > msg->buf->len) {
        GST_DEBUG_OBJECT (client->server, "Not enough data");
        return FALSE;
      }
      client->read_seq = load_be32 (&msg->buf->data[pos]);
      break;

    case MSG_SET_CHUNK:
      if (pos + 4 > msg->buf->len) {
        GST_DEBUG_OBJECT (client->server, "Not enough data");
        return FALSE;
      }
      client->recv_chunk_size = load_be32 (&msg->buf->data[pos]);
      GST_DEBUG_OBJECT (client->server, "receive chunk size set to %d",
          client->recv_chunk_size);
      break;

    case MSG_USER_CONTROL:
    {
      guint16 method = load_be16 (&msg->buf->data[pos]);
      if (method == 6)
      {
        guint32 timestamp = load_be32 (&msg->buf->data[pos+2]);
        ret = client_handle_user_control (client, timestamp);
      }
      break;
    }

    case MSG_WINDOW_ACK_SIZE:
    {
      client->window_size = load_be32 (&msg->buf->data[pos]);
      GST_DEBUG_OBJECT (client->server, "%s window size set to %u",
          client->path, client->window_size);
      break;
    }

    case MSG_SET_PEER_BW:
    {
      client->window_size = load_be32 (&msg->buf->data[pos]);
      GST_DEBUG_OBJECT (client->server, "%s Got Set Peer BW msg, window size set to %u",
          client->path, client->window_size);

      // Send back the expected Window Ack Msg
      AmfEnc * invoke = amf_enc_new ();
      amf_enc_add_int (invoke, htonl (client->window_size));
      client_rtmp_send (client, MSG_WINDOW_ACK_SIZE, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
      amf_enc_free (invoke);
      break;
    }

    case MSG_INVOKE:
    {
      AmfDec * dec = amf_dec_new (msg->buf, 0);
      ret = client_handle_invoke (client, msg, dec);
      amf_dec_free (dec);
      break;
    }

    case MSG_INVOKE3:
    {
      AmfDec * dec = amf_dec_new (msg->buf, 1);
      ret = client_handle_invoke (client, msg, dec);
      amf_dec_free (dec);
      break;
    }

    case MSG_NOTIFY:
    {
      AmfDec * dec = amf_dec_new (msg->buf, 0);
      gchar * type = amf_dec_load_string (dec);
      GST_DEBUG_OBJECT (client->server, "notify %s", type);
      if (msg->msg_stream_id == client->msg_stream_id) {
        if (strcmp (type, "@setDataFrame") == 0) {
          client_handle_setdataframe (client, dec);
        }
      }
      g_free (type);
      amf_dec_free (dec);
      break;
    }

    case MSG_DATA:
    {
      AmfDec * dec = amf_dec_new (msg->buf, 1);
      gchar * type = amf_dec_load_string (dec);
      GST_DEBUG_OBJECT (client->server, "data %s", type);
      if (msg->msg_stream_id == client->msg_stream_id) {
        if (strcmp (type, "@setDataFrame") == 0) {
          client_handle_setdataframe (client, dec);
        }
      }
      g_free (type);
      amf_dec_free (dec);
      break;
    }

    case MSG_AUDIO:
      if (!client->publisher) {
        GST_DEBUG_OBJECT (client->server, "not a publisher");
        return FALSE;
      }
      GSList * subscribers =
          connections_get_subscribers (client->connections, client->path);
      for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
        Client * subscriber = (Client *)walk->data;

/* FIXME: this is the best way, can we make it so ?
        client_rtmp_send (subscriber, MSG_AUDIO, subscriber->msg_stream_id,
            msg->buf, msg->timestamp, msg->fmt, CHUNK_STREAM_ID_CONTROL);
*/
        client_rtmp_send (subscriber, MSG_AUDIO, subscriber->msg_stream_id,
            msg->buf, msg->abs_timestamp, CHUNK_STREAM_ID_STREAM);
      }
      break;


    case MSG_VIDEO:
    {
      if (!client->publisher) {
        GST_DEBUG_OBJECT (client->server, "not a publisher");
        return FALSE;
      }
      guint8 flags = msg->buf->data[0];
      GSList * subscribers =
          connections_get_subscribers (client->connections, client->path);
      for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
        Client * subscriber = (Client *)walk->data;

        if (flags >> 4 == FLV_KEY_FRAME && !subscriber->ready) {
          subscriber->ready = TRUE;
        }
        if (subscriber->ready) {
          client_rtmp_send (subscriber, MSG_VIDEO, subscriber->msg_stream_id,
              msg->buf, msg->abs_timestamp, CHUNK_STREAM_ID_STREAM);
        }
      }
      break;
    }

    case MSG_FLASH_VIDEO:
      GST_WARNING_OBJECT (client->server, "streaming FLV not supported");
      ret = FALSE;
      break;

    default:
      GST_DEBUG_OBJECT (client->server, "unhandled message: %02x", msg->type);
      gst_util_dump_mem (msg->buf->data, msg->buf->len);
      break;
  }

  return ret;
}

static RTMP_Message *
rtmp_message_new ()
{
  RTMP_Message * msg = g_new0 (RTMP_Message, 1);
  msg->buf = g_byte_array_new ();
  return msg;
}

static void
rtmp_message_free (RTMP_Message * msg)
{
  g_byte_array_free (msg->buf, TRUE);
  g_free (msg);
}

static RTMP_Message *
client_get_rtmp_message (Client * client, guint8 chunk_stream_id)
{
  RTMP_Message * msg = g_hash_table_lookup (client->rtmp_messages,
      GINT_TO_POINTER (chunk_stream_id));
  if (msg == NULL) {
    msg = rtmp_message_new ();
    g_hash_table_insert (client->rtmp_messages,
        GINT_TO_POINTER (chunk_stream_id), msg);
  }
  return msg;
}

static gboolean
client_incoming_handshake (Client * client)
{
  if (client->handshake_state == HANDSHAKE_START) {
    guint len = HANDSHAKE_LENGTH + 1;
    if (client->buf->len >= len) {
      /* receive the handshake from the client */
      if (!pex_rtmp_handshake_process (client->handshake, client->buf->data, len)) {
        GST_WARNING_OBJECT (client->server, "Unable to process handshake");
        return FALSE;
      }
      client->buf = g_byte_array_remove_range (client->buf, 0, len);

      /* send a reply */
      client->send_queue = g_byte_array_append (client->send_queue,
          pex_rtmp_handshake_get_buffer (client->handshake),
          pex_rtmp_handshake_get_length (client->handshake));
      if (!client_try_to_send (client, NULL)) {
        GST_WARNING_OBJECT (client->server, "Unable to send handshake reply");
        return FALSE;
      }

      client->handshake_state = HANDSHAKE_STAGE1;
    }
  } else if (client->handshake_state == HANDSHAKE_STAGE1) {
    guint len = HANDSHAKE_LENGTH;
    if (client->buf->len >= len) {
      /* receive another handshake */
      if (!pex_rtmp_handshake_verify_reply (client->handshake, client->buf->data)) {
        GST_WARNING_OBJECT (client->server, "Could not verify handshake reply");
        return FALSE;
      }
      client->buf = g_byte_array_remove_range (client->buf, 0, len);

      client->handshake_state = HANDSHAKE_DONE;
    }
  }
  return TRUE;
}

static gboolean
client_outgoing_handshake (Client * client)
{
  if (client->handshake_state == HANDSHAKE_START) {
    guint8 buf[HANDSHAKE_LENGTH + 1];
    /* first byte is Handshake Type */
    buf[0] = HANDSHAKE_PLAINTEXT;
    /* Next 4 is Uptime, and 4 more is FMS version */
    /* we set everything to 0 */
    memset (&buf[1], 0, 8);
    /* rest of the buffer is random numbers */
    for (gint i = 9; i < HANDSHAKE_LENGTH + 1; i++)
        buf[i] = 1; /* 1 is random... */

    client->send_queue = g_byte_array_append (client->send_queue,
        buf, HANDSHAKE_LENGTH + 1);
    if (!client_try_to_send (client, NULL)) {
      GST_WARNING_OBJECT (client->server, "Unable to send outgoing handshake (1)");
      return FALSE;
    }

    client->handshake_state = HANDSHAKE_STAGE1;
  } else if (client->handshake_state == HANDSHAKE_STAGE1) {
    guint len = HANDSHAKE_LENGTH + 1;
    if (client->buf->len >= len) {
      /* check that the first byte says PLAINTEXT */
      if (client->buf->data[0] != HANDSHAKE_PLAINTEXT) {
        GST_WARNING_OBJECT (client->server, "Handshake is not plaintext");
        return FALSE;
      }
      client->buf = g_byte_array_remove_range (client->buf, 0, 1);

      guint32 server_uptime;
      guint8 fms_version[4];
      memcpy (&server_uptime, &client->buf->data[0], 4);
      memcpy (&fms_version,   &client->buf->data[4], 4);
      server_uptime = ntohl (server_uptime);
      GST_DEBUG_OBJECT (client->server,
          "Server Uptime: %u, FMS Version: %u.%u.%u.%u", server_uptime,
          fms_version[0], fms_version[1], fms_version[2], fms_version[3]);

      client->send_queue = g_byte_array_append (client->send_queue,
          &client->buf->data[0], HANDSHAKE_LENGTH);
      if (!client_try_to_send (client, NULL)) {
        GST_WARNING_OBJECT (client->server, "Unable to send outgoing handshake (2)");
        return FALSE;
      }
      client->buf = g_byte_array_remove_range (client->buf, 0, HANDSHAKE_LENGTH);
      client->handshake_state = HANDSHAKE_STAGE2;
    }
  }
  if (client->handshake_state == HANDSHAKE_STAGE2 &&
      client->buf->len >= HANDSHAKE_LENGTH) {
    client->buf = g_byte_array_remove_range (client->buf, 0, HANDSHAKE_LENGTH);
    client_do_connect (client);

    client->handshake_state = HANDSHAKE_DONE;
  }

  return TRUE;
}

gint
client_get_poll_events (Client * client)
{
  gint events;

  if (client->state == CLIENT_TCP_HANDSHAKE_IN_PROGRESS) {
    events = POLLOUT;
  } else if (client->state == CLIENT_TLS_HANDSHAKE_IN_PROGRESS) {
    events = POLLIN | POLLOUT;
  } else if (client->send_queue->len > 0 || client->ssl_read_blocked_on_write) {
    events = POLLIN | POLLOUT;
  } else {
    events = POLLIN;
  }

  return events;
}

static gboolean
client_connected (Client * client)
{
  gboolean ret = TRUE;
  client->state = CLIENT_CONNECTED;

  if (client->dialout_path) {
    ret = client_outgoing_handshake (client);
  }

  return ret;
}

static void
print_ssl_errors (Client * client)
{
  char tmp[4096];
  gint error;
  while ((error = ERR_get_error ()) != 0) {
    memset (tmp, 0, sizeof (tmp));
    ERR_error_string_n (error, tmp, sizeof (tmp) - 1);
    GST_WARNING_OBJECT (client->server, "ssl-error: %s", tmp);
  }
}

static gboolean
client_drive_ssl (Client * client)
{
  int ret;

  if (client->dialout_path) {
    ret = SSL_connect (client->ssl);
  } else {
    ret = SSL_accept (client->ssl);
  }

  /* The meaning of ret is as follows:
   * <0: The TLS handshake failed uncleanly
   * 0 : The TLS handshake failed cleanly
   * 1 : The TLS handshake was successful
   */
  if (ret != 1) {
    int error = SSL_get_error (client->ssl, ret);
    /* We're non-blocking, so tolerate the associated errors */
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
      GST_WARNING_OBJECT (client->server, "Unable to establish ssl-connection");
      print_ssl_errors (client);
      return FALSE;
    }
  } else {
    return client_connected (client);
  }

  return TRUE;
}

static gboolean
client_begin_ssl (Client * client)
{
  client->ssl = SSL_new (client->ssl_ctx);
  SSL_set_app_data (client->ssl, client);
  SSL_set_fd (client->ssl, client->fd);

  client->state = CLIENT_TLS_HANDSHAKE_IN_PROGRESS;

  return client_drive_ssl (client);
}

gboolean
client_try_to_send (Client * client, gboolean *connect_failed)
{
  if (connect_failed) {
    *connect_failed = FALSE;
  }

  if (client->state == CLIENT_TCP_HANDSHAKE_IN_PROGRESS) {
    int error;
    socklen_t error_len = sizeof(error);

    getsockopt (client->fd, SOL_SOCKET, SO_ERROR, (void *)&error, &error_len);

    if (error != 0) {
      GST_WARNING_OBJECT (client->server, "error in client TCP handshake (%s): %s",
          client->path, strerror (error));
      if (connect_failed) {
        *connect_failed = TRUE;
      }
      return FALSE;
    }

    if (client->use_ssl) {
      return client_begin_ssl (client);
    }

    return client_connected (client);
  } else if (client->state == CLIENT_TLS_HANDSHAKE_IN_PROGRESS) {
    return client_drive_ssl (client);
  }

  ssize_t written;

  if (client->use_ssl) {
    if (client->ssl_read_blocked_on_write) {
      return client_receive (client);
    } else if (client->send_queue->len == 0) {
      return TRUE;
    }
    client->ssl_write_blocked_on_read = FALSE;
    written = SSL_write (client->ssl,
        client->send_queue->data, client->send_queue->len);
    if (written <= 0) {
      int error = SSL_get_error (client->ssl, written);
      if (error == SSL_ERROR_WANT_READ) {
        client->ssl_write_blocked_on_read = TRUE;
        return TRUE;
      } else if (error == SSL_ERROR_WANT_WRITE) {
        return TRUE;
      }

      GST_WARNING_OBJECT (client->server, "unable to write to a client (%s)",
          client->path);
      print_ssl_errors (client);
      return FALSE;
    }
  } else {
    #ifdef __APPLE__
    written = send (client->fd,
        client->send_queue->data, client->send_queue->len, 0);
    #else
    written = send (client->fd,
        client->send_queue->data, client->send_queue->len, MSG_NOSIGNAL);
    #endif
    if (written < 0) {
      if (errno == EAGAIN || errno == EINTR)
        return TRUE;
      GST_WARNING_OBJECT (client->server, "unable to write to a client (%s): %s",
          client->path, strerror (errno));
      return FALSE;
    }
  }

  if (written > 0) {
    client->send_queue = g_byte_array_remove_range (client->send_queue, 0, written);
  }
  return TRUE;
}

gboolean
client_receive (Client * client)
{
  guint8 chunk[4096];
  gint got;

  if (client->state == CLIENT_TLS_HANDSHAKE_IN_PROGRESS) {
    return client_drive_ssl (client);
  }

  if (client->use_ssl) {
    if (client->ssl_write_blocked_on_read) {
      return client_try_to_send (client, NULL);
    }
    client->ssl_read_blocked_on_write = FALSE;
    got = SSL_read (client->ssl, &chunk[0], sizeof (chunk));
    if (got <= 0) {
      int error = SSL_get_error (client->ssl, got);
      if (error == SSL_ERROR_WANT_READ) {
        return TRUE;
      } else if (error == SSL_ERROR_WANT_WRITE) {
        client->ssl_read_blocked_on_write = TRUE;
        return TRUE;
      }
      GST_DEBUG_OBJECT (client->server, "unable to read from a client");
      return FALSE;
    }
    client->buf = g_byte_array_append (client->buf, chunk, got);
    GST_LOG_OBJECT (client->server, "Read %d bytes", got);
    GST_MEMDUMP_OBJECT (client->server, "Message contents", chunk, got);

    int remaining = SSL_pending (client->ssl);
    while (remaining > 0) {
      int len = sizeof (chunk);
      if (remaining < len) {
        len = remaining;
      }
      got = SSL_read (client->ssl, &chunk[0], len);
      if (got <= 0) {
        GST_WARNING_OBJECT (client->server, "unable to read from ssl buffer");
        return FALSE;
      }

      client->buf = g_byte_array_append (client->buf, chunk, got);
      GST_LOG_OBJECT (client->server, "Read %d bytes", got);
      GST_MEMDUMP_OBJECT (client->server, "Message contents", chunk, got);

      remaining -= got;
    }
  } else {
    got = recv (client->fd, &chunk[0], sizeof (chunk), 0);
    if (got == 0) {
      GST_DEBUG_OBJECT (client->server, "EOF from a client");
      return FALSE;
    } else if (got < 0) {
      if (errno == EAGAIN || errno == EINTR)
        return TRUE;
      GST_DEBUG_OBJECT (client->server, "unable to read from a client: %s",
          strerror (errno));
      return FALSE;
    }
    client->buf = g_byte_array_append (client->buf, chunk, got);
    GST_LOG_OBJECT (client->server, "Read %d bytes", got);
    GST_MEMDUMP_OBJECT (client->server, "Message contents", chunk, got);
  }

  if (client->handshake_state != HANDSHAKE_DONE) {
    gboolean ret;
    if (client->dialout_path) {
      ret = client_outgoing_handshake (client);
    } else {
      ret = client_incoming_handshake (client);
    }
    if (client->handshake_state != HANDSHAKE_DONE)
      return ret;
  }

  while (client->buf->len != 0) {
    guint8 flags = client->buf->data[0];
    guint8 fmt = flags >> 6; /* 5.3.1.2 */
    guint8 chunk_stream_id = flags & 0x3f;
    guint header_len = CHUNK_MSG_HEADER_LENGTH[fmt];

    if (client->buf->len < header_len) {
      /* need more data */
      break;
    }

    RTMP_Header * header = (RTMP_Header *)&client->buf->data[0];
    RTMP_Message * msg = client_get_rtmp_message (client, chunk_stream_id);

    /* only get the message fmt from beginning of a new message */
    if (msg->buf->len == 0) {
      msg->fmt = fmt;
    }

    if (header_len >= 8) {
      msg->len = load_be24 (header->msg_len);
      if (msg->len < msg->buf->len) {
        GST_WARNING_OBJECT (client->server, "invalid msg length");
        return FALSE;
      }
      msg->type = header->msg_type_id;
    }

    if (msg->len == 0) {
      GST_WARNING_OBJECT (client->server, "message with 0 length");
      return FALSE;
    }

    if (header_len >= 12) {
      msg->msg_stream_id = header->msg_stream_id;
    }

    /* timestamp */
    if (header_len >= 4) {
      msg->timestamp = load_be24 (header->timestamp);
      /* extended timestamps are always absolute */
      if (msg->timestamp == EXT_TIMESTAMP_LIMIT) {
        GST_DEBUG_OBJECT (client->server, "Using extended timestamp");
        msg->abs_timestamp = load_be32 (&client->buf->data[header_len]);
        header_len += 4;
      } else {
        /* for type 0 we receive the absolute timestamp,
           for type 1, 2, and 3 we get a delta */
        if (fmt == 0)
          msg->abs_timestamp = msg->timestamp;
        else
          msg->abs_timestamp += msg->timestamp;
      }
    }

    /* For a type 3 msg, increment with previous delta.
       Note that this don't apply to "continuation" type 3,
       that is used to split a single message into chunk-sizes
     */
    if (msg->buf->len == 0 && fmt == 3) {
      msg->abs_timestamp += msg->timestamp;
    }

    GST_LOG_OBJECT (client->server,
        "Received timestamp: %u and abs-timestamp: %u in ",
        msg->timestamp, msg->abs_timestamp);

    /* with extended timestamp, Flash embeds that timestamp after the fmt=3
       when dividing into chunks */
    if (msg->timestamp == EXT_TIMESTAMP_LIMIT && fmt == 3 && msg->buf->len > 0)
      header_len += 4;

    guint chunk_size = msg->len - msg->buf->len;
    if (chunk_size > client->recv_chunk_size)
      chunk_size = client->recv_chunk_size;

    if (client->buf->len < header_len + chunk_size) {
      /* need more data */
      break;
    }

    GST_LOG_OBJECT (client->server,
        "Appending a chunk of %u bytes of data to message, "
        "skipping %u bytes of header (type: %u)", chunk_size, header_len, fmt);
    msg->buf = g_byte_array_append (msg->buf, &client->buf->data[header_len], chunk_size);
    client->buf = g_byte_array_remove_range (client->buf, 0, header_len + chunk_size);

    if (msg->buf->len == msg->len) {
      if (!client_handle_message (client, msg))
        return FALSE;
      msg->buf = g_byte_array_remove_range (msg->buf, 0, msg->buf->len);
    }
  }
  return TRUE;
}

static int
match_dns_name (const gchar * remote_host, ASN1_IA5STRING * candidate)
{
  const gchar * data = (gchar *) ASN1_STRING_data (candidate);
  int len = ASN1_STRING_length (candidate);
  int host_len = strlen (remote_host);

  if ((int) strnlen (data, len) != len) {
    /* Candidate contains embedded NULs: reject it */
    return 0;
  }

  /* See RFC6125 $6.4. We assume that any IDN has been pre-normalised
   * to remove any U-labels. */
  if (len == host_len && g_ascii_strncasecmp (remote_host, data, len) == 0) {
    /* Exact match */
    return 1;
  }

  if (g_hostname_is_ip_address (remote_host)) {
    /* Do not attempt to match wildcards against IP addresses */
    return 0;
  }

  /* Wildcards: permit the left-most label to be '*' only and match
   * the left-most reference label */
  if (len > 1 && data[0] == '*' && data[1] == '.') {
    const gchar * host_suffix = strchr (remote_host, '.');
    if (host_suffix == NULL || host_suffix == remote_host) {
      /* No dot found, or remote_host starts with a dot: reject */
      return 0;
    }

    if (len - 1 == host_len - (host_suffix - remote_host) &&
        g_ascii_strncasecmp (host_suffix, data + 1, len - 1) == 0) {
      /* Wildcard matched */
      return 1;
    }
  }

  return 0;
}

static int
match_subject_alternative_names (X509 * cert, const gchar * remote_host)
{
  int result = -1;
  GENERAL_NAMES * san;

  san = X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);
  if (san != NULL) {
    int idx = sk_GENERAL_NAME_num (san);
    enum {
      HOST_TYPE_DNS = 0,
      HOST_TYPE_IPv4 = sizeof(struct in_addr),
      HOST_TYPE_IPv6 = sizeof(struct in6_addr)
    } host_type;
    int num_sans_for_type = 0;
    struct in6_addr addr;

    if (inet_pton (AF_INET6, remote_host, &addr)) {
      host_type = HOST_TYPE_IPv6;
    } else if (inet_pton (AF_INET, remote_host, &addr)) {
      host_type = HOST_TYPE_IPv4;
    } else {
      host_type = HOST_TYPE_DNS;
    }

    while (--idx >= 0) {
      int type;
      void * value;
     
      value = GENERAL_NAME_get0_value (sk_GENERAL_NAME_value (san, idx), &type);

      if (type == GEN_DNS && host_type == HOST_TYPE_DNS) {
        num_sans_for_type++;
        if (match_dns_name (remote_host, value)) {
          break;
        }
      } else if (type == GEN_IPADD && host_type != HOST_TYPE_DNS) {
        int len = ASN1_STRING_length (value);
        num_sans_for_type++;
        if (len == (int) host_type &&
            memcmp (ASN1_STRING_data (value), &addr, len) == 0) {
          break;
        }
      }     
    }

    GENERAL_NAMES_free (san);

    if (num_sans_for_type > 0) {
      result = (idx >= 0);
    }
  }

  /* -1 if no applicable SANs present; 0 for no match; 1 for match */
  return result;
}

static int
match_subject_common_name (X509 * cert, const gchar * remote_host)
{
  X509_NAME * subject = X509_get_subject_name (cert);

  if (subject != NULL) {
    int idx = X509_NAME_entry_count (subject);

    while (--idx >= 0) {
      X509_NAME_ENTRY * entry = X509_NAME_get_entry (subject, idx);
      if (OBJ_obj2nid (X509_NAME_ENTRY_get_object (entry)) == NID_commonName) {
        return match_dns_name (remote_host, X509_NAME_ENTRY_get_data (entry));
      }
    }
  }

  return 0;
}

static int
verify_hostname (X509 * cert, const gchar * remote_host)
{
  /* See RFC2818 $3.1 */
  int result = match_subject_alternative_names (cert, remote_host);

  if (result == -1) {
    result = match_subject_common_name (cert, remote_host);
  }

  return result;
}

static int
ssl_verify_callback (int preverify_ok, X509_STORE_CTX *ctx)
{
  SSL * ssl = X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx ());
  Client * client = SSL_get_app_data (ssl);
  X509 * current_cert = X509_STORE_CTX_get_current_cert (ctx);

  if (preverify_ok == 0 || current_cert == NULL) {
    return preverify_ok;
  }

  /* TODO: Perform OCSP check for current certificate */

  if (current_cert == ctx->cert) {
    /* The current certificate is the peer certificate */
    if (client->remote_host != NULL) {
      preverify_ok = verify_hostname(current_cert, client->remote_host);
    }
  }

  return preverify_ok;
}

static gboolean
file_exists (const gchar *path)
{
  if (path == NULL || path[0] == '\0') {
    return FALSE;
  }
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

static DH *
make_dh_params (const gchar *cert_file)
{
  DH * dh = NULL;
  BIO * bio = BIO_new_file (cert_file, "r");

  if (bio != NULL) {
    X509 * cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
    BIO_free (bio);

    if (cert != NULL) {
      EVP_PKEY * pubkey = X509_get_pubkey (cert);
      if (pubkey != NULL) {
        static const struct {
          int size;
          BIGNUM * (*prime) (BIGNUM *);
        } gentable[] = {
          { 2048, get_rfc3526_prime_2048 },
          { 3072, get_rfc3526_prime_3072 },
          { 4096, get_rfc3526_prime_4096 },
          { 6144, get_rfc3526_prime_6144 },
          { 8192, get_rfc3526_prime_8192 }
        };
        size_t idx;
        int keylen = 2048;
        int type = EVP_PKEY_type (pubkey->type);
        if (type == EVP_PKEY_RSA || type == EVP_PKEY_DSA) {
          keylen = EVP_PKEY_bits (pubkey);
        }
        EVP_PKEY_free (pubkey);

        for (idx = 0; idx < sizeof (gentable) / sizeof (gentable[0]); idx++) {
          if (keylen <= gentable[idx].size) {
            break;
          }
        }
        if (idx == sizeof (gentable) / sizeof (gentable[0])) {
          idx--;
        }

        dh = DH_new();
        if (dh != NULL) {
          dh->p = gentable[idx].prime (NULL);
          BN_dec2bn (&dh->g, "2");
          if (dh->p == NULL || dh->g == NULL) {
            DH_free (dh);
            dh = NULL;
          }
        }
      }
      X509_free (cert);
    }
  }

  return dh;
}

gboolean
client_add_incoming_ssl (Client * client,
    const gchar * cert_file, const gchar * key_file,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean ssl3_enabled)
{
  BIO * bio;
  long ssl_options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE;

  client->ssl_ctx = SSL_CTX_new (SSLv23_server_method());

  if (!ssl3_enabled) {
    ssl_options |= SSL_OP_NO_SSLv3;
  }

  SSL_CTX_set_cipher_list (client->ssl_ctx, ciphers);
  SSL_CTX_set_options (client->ssl_ctx, ssl_options);
  if (file_exists (ca_file)) {
    SSL_CTX_load_verify_locations (client->ssl_ctx, ca_file, NULL);
  }
  if (file_exists (ca_dir)) {
    SSL_CTX_load_verify_locations (client->ssl_ctx, NULL, ca_dir);
  }
  SSL_CTX_set_verify (client->ssl_ctx, SSL_VERIFY_NONE, ssl_verify_callback);
  SSL_CTX_set_mode (client->ssl_ctx,
      SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  if (file_exists (cert_file) && file_exists (key_file)) {
    if (SSL_CTX_use_certificate_file (client->ssl_ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
      GST_WARNING_OBJECT (client->server, "did not like the certificate: %s", cert_file);
      print_ssl_errors (client);
      return FALSE;
    }

    if (SSL_CTX_use_PrivateKey_file (client->ssl_ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
      GST_WARNING_OBJECT (client->server, "did not like the key: %s", key_file);
      print_ssl_errors (client);
      return FALSE;
    }

    /* Configure DH parameters */
    bio = BIO_new_file (cert_file, "r");
    if (bio != NULL) {
      DH * dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);  
      BIO_free (bio);

      if (dh == NULL) {
        dh = make_dh_params (cert_file);
      }

      if (dh != NULL) {
        SSL_CTX_set_tmp_dh (client->ssl_ctx, dh);
        DH_free (dh);
      }
    }

    /* Configure ECDH parameters */
    bio = BIO_new_file (cert_file, "r");
    if (bio != NULL) {
      EC_KEY * key;
      int nid = NID_X9_62_prime256v1;
      EC_GROUP * group = PEM_read_bio_ECPKParameters (bio, NULL, NULL, NULL);
      BIO_free (bio);

      if (group != NULL) {
        nid = EC_GROUP_get_curve_name (group);
        if (nid == NID_undef) {
          nid = NID_X9_62_prime256v1;
        }

        EC_GROUP_free (group);
      }

      key = EC_KEY_new_by_curve_name (nid);
      if (key != NULL) {
        SSL_CTX_set_tmp_ecdh (client->ssl_ctx, key);
        EC_KEY_free (key);
      }
    }

    ERR_clear_error();
  }

  return TRUE;
}

gboolean
client_add_outgoing_ssl (Client * client,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean ssl3_enabled)
{
  long ssl_options = SSL_OP_ALL | SSL_OP_NO_SSLv2;

  client->ssl_ctx = SSL_CTX_new (SSLv23_client_method());

  if (!ssl3_enabled) {
    ssl_options |= SSL_OP_NO_SSLv3;
  }

  SSL_CTX_set_cipher_list (client->ssl_ctx, ciphers);
  SSL_CTX_set_options (client->ssl_ctx, ssl_options);
  if (file_exists (ca_file)) {
    SSL_CTX_load_verify_locations (client->ssl_ctx, ca_file, NULL);
  }
  if (file_exists (ca_dir)) {
    SSL_CTX_load_verify_locations (client->ssl_ctx, NULL, ca_dir);
  }
  SSL_CTX_set_verify (client->ssl_ctx,
      SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_callback);
  SSL_CTX_set_mode (client->ssl_ctx,
      SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  return TRUE;
}

Client *
client_new (gint fd, Connections * connections, GObject * server,
    gboolean use_ssl, gint stream_id, guint chunk_size,
    const gchar * remote_host)
{
  Client * client = g_new0 (Client, 1);

  client->fd = fd;
  client->state = CLIENT_TCP_HANDSHAKE_IN_PROGRESS;
  client->connections = connections;
  client->server = server;
  client->use_ssl = use_ssl;
  client->msg_stream_id = stream_id;
  client->chunk_size = chunk_size;
  client->recv_chunk_size = DEFAULT_CHUNK_SIZE;
  client->send_chunk_size = DEFAULT_CHUNK_SIZE;

  GST_DEBUG_OBJECT (client->server, "Chunk Size: %d, Stream ID:%d\n",
      chunk_size, stream_id);

  client->window_size = DEFAULT_WINDOW_SIZE;

  client->rtmp_messages = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify)rtmp_message_free);

  client->send_queue = g_byte_array_new ();
  client->buf = g_byte_array_new ();

  client->handshake = pex_rtmp_handshake_new ();
  client->handshake_state = HANDSHAKE_START;

  if (remote_host != NULL) {
    client->remote_host = g_strdup (remote_host);
  }

  return client;
}

void
client_free (Client * client)
{
  g_hash_table_destroy (client->rtmp_messages);

  g_byte_array_free (client->buf, TRUE);
  g_byte_array_free (client->send_queue, TRUE);

  if (client->metadata)
    gst_structure_free (client->metadata);
  g_free (client->path);
  g_free (client->tcUrl);
  g_free (client->app);
  g_free (client->dialout_path);
  g_free (client->url);
  g_free (client->addresses);

  pex_rtmp_handshake_free (client->handshake);

  /* ssl */
  if (client->ssl_ctx)
    SSL_CTX_free (client->ssl_ctx);
  if (client->ssl)
    SSL_free (client->ssl);
  g_free (client->remote_host);

  g_free (client);
}
