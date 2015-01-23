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
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug
#define debug(fmt...) GST_DEBUG(fmt)
#define warning(fmt...) GST_WARNING(fmt)

static gboolean
is_safe (guint8 b)
{
  return b >= ' ' && b < 128;
}

static void
hexdump (const void *buf, size_t len)
{
  const guint8 * data = (const guint8 *) buf;
  for (size_t i = 0; i < len; i += 16) {
    for (int j = 0; j < 16; ++j) {
      if (i + j < len)
        debug ("%.2x ", data[i + j]);
      else
        debug ("   ");
    }
    for (int j = 0; j < 16; ++j) {
      if (i + j < len) {
        putc (is_safe (data[i + j]) ? data[i + j] : '.', stdout);
      } else {
        putc (' ', stdout);
      }
    }
    putc ('\n', stdout);
  }
}

gboolean
client_try_to_send (Client * client)
{
  guint len = client->send_queue->len;

  if (len > 4096)
    len = 4096;

  ssize_t written;

  if (client->use_ssl) {
    written = SSL_write (client->ssl,
        client->send_queue->data, client->send_queue->len);
  } else {
    #ifdef __APPLE__
    written = send (client->fd,
        client->send_queue->data, client->send_queue->len, 0);
    #else
    written = send (client->fd,
        client->send_queue->data, client->send_queue->len, MSG_NOSIGNAL);
    #endif
  }

  if (written < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    warning ("unable to write to a client (%s): %s", client->path, strerror (errno));
    return FALSE;
  }

  if (written > 0) {
    client->send_queue = g_byte_array_remove_range (client->send_queue, 0, written);
  }
  return TRUE;
}

static void
client_rtmp_send (Client * client, guint8 type, guint32 msg_stream_id,
    GByteArray * buf, guint32 timestamp, guint8 chunk_stream_id)
{
  RTMP_Header header;
  const gint fmt = 0; /* FIXME: start storing last header and b more clever here */
  chunk_stream_id &= 0x3f;
  header.flags = chunk_stream_id | (fmt << 6);
  header.msg_type = type;
  set_be24 (header.timestamp, timestamp);
  set_be24 (header.msg_len, buf->len);
  set_le32 (header.msg_stream_id, msg_stream_id);
  size_t header_len = CHUNK_MSG_HEADER_LENGTH[fmt];
  debug ("Sending packet with:\n"
      "format:%d, chunk_stream_id:%u, timestamp:%u, len:%u, type:%u, msg_stream_id:%u",
      fmt, chunk_stream_id, timestamp, buf->len, type, msg_stream_id);
  client->send_queue = g_byte_array_append (client->send_queue,
      (guint8 *)&header, header_len);

  client->written_seq += header_len;

  size_t pos = 0;
  while (pos < buf->len) {
    if (pos) {
      guint8 flags = chunk_stream_id | (3 << 6);
      client->send_queue = g_byte_array_append (client->send_queue, &flags, 1);
      client->written_seq += 1;
    }

    size_t chunk = buf->len - pos;
    if (chunk > client->chunk_size)
      chunk = client->chunk_size;
    client->send_queue = g_byte_array_append (client->send_queue,
        &buf->data[pos], chunk);

    client_try_to_send (client);

    client->written_seq += chunk;
    pos += chunk;
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
client_handle_result (Client * client, gint txid, AmfDec * dec)
{
  /* we won't handle this unless we are dialing out to a path */
  if (client->dialout_path == NULL)
    return;

  (void)dec;
  debug ("Handling result for txid %d", txid);

  if (txid == 1) {
    debug ("Sending releaseStream + FCPublish + createStream");
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
    debug("Got message stream id %d", client->msg_stream_id);
    g_value_unset (reply);
    g_value_unset (status);
    g_free (reply);
    g_free (status);

    debug ("Sending publish");
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
client_handle_onstatus (Client * client, double txid, AmfDec * dec, gint stream_id)
{
  (void)txid;
  /* we won't handle this unless we are dialing out to a path */
  if (client->dialout_path == NULL)
    return;

  gboolean reject_play = FALSE;
  g_signal_emit_by_name (client->server, "on-play", client->path, &reject_play);
  if (reject_play) {
    debug ("%p Not playing due to signal returning 0", client);
    return;
  }

  g_free (amf_dec_load (dec));           /* NULL */
  GstStructure * object = amf_dec_load_object (dec);

  const gchar * code = gst_structure_get_string (object, "code");
  debug ("onStatus - code: %s", code);
  if (code && g_strcmp0 (code, "NetStream.Publish.Start") == 0) {
    /* make the client a subscriber on the local server */
    connections_add_subscriber (client->connections, client, client->path);

    GstStructure * meta = gst_structure_new ("object",
        "videocodecid", G_TYPE_STRING, "avc1",
        "profile", G_TYPE_STRING, "baseline",
        "fps", G_TYPE_DOUBLE, 30.0,
        "framerate", G_TYPE_DOUBLE, 30.0,
        "keyFrameInterval", G_TYPE_DOUBLE, 48.0,
        "codec", G_TYPE_STRING, "H264Avc",
        "level", G_TYPE_STRING, "3.1",
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
  }

  gst_structure_free (object);
}

void
client_do_connect (Client * client, const gchar * tcUrl,
    const gchar * application_name, const gchar * path)
{
  #define SUPPORT_SND_AAC   0x0400
  #define SUPPORT_SND_SPEEX 0x0800
  #define SUPPORT_VID_H264  0x0080

  debug ("connecting to: %s with path: %s", tcUrl, path);

  /* make a copy of the path to connect to */
  client->dialout_path = g_strdup (path);

  /* send connect */
  GstStructure * status = gst_structure_new ("object",
      "app", G_TYPE_STRING, application_name,
      "tcUrl", G_TYPE_STRING, tcUrl,
      "type", G_TYPE_STRING, "nonprivate",
      "flashVer", G_TYPE_STRING, "FMLE/3.0 (compatible; FMSc/1.0)",
      "swfUrl", G_TYPE_STRING, tcUrl,
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
}

static void
client_handle_connect (Client * client, double txid, AmfDec * dec)
{
  AmfEnc * invoke;
  GstStructure * params = amf_dec_load_object (dec);

  /* FIXME: support multiple applications */
  //if (strcmp (app, application_name) != 0) {
  //  g_warning ("Unsupported application: %s", app);
  //}

  gchar * params_str = gst_structure_to_string (params);
  debug ("connect: %s", params_str);
  g_free (params_str);
  gst_structure_free (params);

  // Send win ack size
  invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (client->window_size));
  client_rtmp_send (client, MSG_WINDOW_ACK_SIZE, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);

  // Send set peer bandwidth
  invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (5000000));
  amf_enc_add_char (invoke, AMF_DYNAMIC);
  client_rtmp_send (client, MSG_SET_PEER_BW, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);

  // Send set chunk size
  invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (client->chunk_size));
  client_rtmp_send(client, MSG_SET_CHUNK, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);

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
  debug ("fcpublish %s", path);

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
  debug ("publish %s", path);

  client->publisher = TRUE;
  g_free (client->path);
  client->path = path;

  gboolean reject_publish = FALSE;
  g_signal_emit_by_name(client->server, "on-publish", path, &reject_publish);
  if (reject_publish) {
    debug ("Not publishing due to signal rejecting publish");
    return FALSE;
  }
  connections_add_publisher (client->connections, client, path);
  debug ("publisher connected.");

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
  debug("(%s) METADATA %"GST_PTR_FORMAT, client->path, metadata);
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
    debug ("%p Not playing due to signal returning 0", client);
    return FALSE;
  }
  debug ("play %s", path);

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
  debug ("play2 %s", path);
  gst_structure_free (params);

  client_start_playback (client);

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);
}

static void
client_handle_pause (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));           /* NULL */

  gboolean paused = amf_dec_load_boolean (dec);
  if (paused) {
    debug ("pausing");

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
    g_warning ("not a publisher");
    return;
  }

  gchar * type = amf_dec_load_string (dec);
  if (strcmp (type, "onMetaData") != 0) {
    g_warning ("can only set metadata");
  }
  g_free (type);

  if (client->metadata)
    gst_structure_free (client->metadata);
  client->metadata = amf_dec_load_object (dec);
  debug ("(%s) METADATA %"GST_PTR_FORMAT, client->path, client->metadata);
}

static gboolean
client_handle_user_control (Client * client, const double method, const double timestamp)
{
  (void) method;
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
  double txid = amf_dec_load_number (dec);

  debug ("%p: invoked %s with txid %lf for Stream Id: %d ", client, method, txid, msg->msg_stream_id);

  if (strcmp (method, "onStatus") == 0) {
    client_handle_onstatus (client, txid, dec, msg->msg_stream_id);
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
  /*
     debug("RTMP message %02x, len %zu, timestamp %ld", msg->type, msg->len,
     msg->timestamp);
   */
  gboolean ret = TRUE;

  /* send window-size ACK if we have reached it */
  client->total_bytes_received += msg->len;
  if (client->publisher) {
    client->bytes_received_since_ack += msg->len;
    if (client_window_size_reached (client))
      client_send_ack (client);
  }

  size_t pos = 0;
  switch (msg->type) {
    case MSG_ACK:
      if (pos + 4 > msg->buf->len) {
        debug ("Not enough data");
        return FALSE;
      }
      client->read_seq = load_be32 (&msg->buf->data[pos]);
      break;

    case MSG_SET_CHUNK:
      if (pos + 4 > msg->buf->len) {
        debug ("Not enough data");
        return FALSE;
      }
      client->chunk_size = load_be32(&msg->buf->data[pos]);
      debug ("chunk size set to %d", (int)client->chunk_size);
      break;

    case MSG_USER_CONTROL:
    {
      double method = load_be16 (&msg->buf->data[pos]);
      if (method == 6)
      {
        double timestamp = load_be32 (&msg->buf->data[pos+2]);
        ret = client_handle_user_control (client, method, timestamp);
      }
      break;
    }

    case MSG_WINDOW_ACK_SIZE:
    {
      client->window_size = load_be32 (&msg->buf->data[pos]);
      debug ("%s window size set to %u", client->path, client->window_size);
      break;
    }

    case MSG_SET_PEER_BW:
    {
      client->window_size = load_be32 (&msg->buf->data[pos]);
      debug ("%s Got Set Peer BW msg, window size set to %u",
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
      debug ("notify %s", type);
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
      debug ("data %s", type);
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
        debug ("not a publisher");
        return FALSE;
      }
      GSList * subscribers = connections_get_subscribers (client->connections, client->path);
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
        debug ("not a publisher");
        return FALSE;
      }
      guint8 flags = msg->buf->data[0];
      GSList * subscribers = connections_get_subscribers (client->connections, client->path);
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
      g_warning ("streaming FLV not supported");
      ret = FALSE;
      break;

    default:
      debug ("unhandled message: %02x", msg->type);
      hexdump (msg->buf->data, msg->buf->len);
      break;
  }

  return ret;
}

gboolean
client_receive (Client * client)
{
  guint8 chunk[4096];
  ssize_t got;

  if (client->use_ssl) {
    got = SSL_read (client->ssl, &chunk[0], sizeof (chunk));
  } else {
    got = recv (client->fd, &chunk[0], sizeof (chunk), 0);
  }

  if (got == 0) {
    debug ("EOF from a client");
    return FALSE;
  } else if (got < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    debug ("unable to read from a client: %s", strerror (errno));
    return FALSE;
  }
  client->buf = g_byte_array_append (client->buf, chunk, got);

  while (client->buf->len != 0) {
    guint8 flags = client->buf->data[0];
    guint8 fmt = flags >> 6; /* 5.3.1.2 */
    guint8 stream_id = flags & 0x3f;
    size_t header_len = CHUNK_MSG_HEADER_LENGTH[fmt];

    if (client->buf->len < header_len) {
      /* need more data */
      break;
    }

    RTMP_Header header;
    memcpy (&header, &client->buf->data[0], header_len);

    RTMP_Message * msg = &client->messages[stream_id];

    /* only get fmt from beginning of a new message */
    if (msg->buf->len == 0) {
      msg->fmt = fmt;
    }

    if (header_len >= 8) {
      msg->len = load_be24 (header.msg_len);
      if (msg->len < msg->buf->len) {
        debug ("invalid msg length");
        return FALSE;
      }
      msg->type = header.msg_type;
    }

    if (msg->len == 0) {
      debug ("message without a header");
      return FALSE;
    }

    if (header_len >= 12) {
      msg->msg_stream_id = load_le32 (header.msg_stream_id);
    }

    /* timestamp */
    if (header_len >= 4) {
      guint32 ts = load_be24 (header.timestamp);
      if (ts == 0xffffff) {
        debug ("ext timestamp not supported");
        return TRUE;
      }
      msg->timestamp = ts;

      /* for type 0 we receive the absolute timestamp, for type 1, 2, and 3 we get a delta */
      if (fmt == 0)
        msg->abs_timestamp = ts;
      else
        msg->abs_timestamp += ts;
    }

    /* for a type 3 msg, increment with previous delta */
    if (msg->fmt == 3) {
      msg->abs_timestamp += msg->timestamp;
    }

    size_t chunk = msg->len - msg->buf->len;
    if (chunk > client->chunk_size)
      chunk = client->chunk_size;

    if (client->buf->len < header_len + chunk) {
      /* need more data */
      break;
    }

    msg->buf = g_byte_array_append (msg->buf, &client->buf->data[header_len], chunk);
    client->buf = g_byte_array_remove_range (client->buf, 0, header_len + chunk);

    if (msg->buf->len == msg->len) {
      if (!client_handle_message (client, msg))
        return FALSE;
      msg->buf = g_byte_array_remove_range (msg->buf, 0, msg->buf->len);
    }
  }
  return TRUE;
}

size_t
client_recv_all (Client * client, void * buf, size_t len)
{
  size_t pos = 0;
  while (pos < len) {
    ssize_t bytes;
    if (client->use_ssl) {
      bytes = SSL_read (client->ssl, (char *)buf + pos, len - pos);
    } else {
      bytes = recv (client->fd, (char *)buf + pos, len - pos, 0);
    }
    if (bytes < 0) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      warning ("unable to recv: %s", strerror (errno));
      return bytes;
    }
    if (bytes == 0)
      break;
    pos += bytes;
  }
  return pos;
}

size_t
client_send_all (Client * client, const void * buf, size_t len)
{
  size_t pos = 0;
  while (pos < len) {
    ssize_t written;
    if (client->use_ssl) {
      written = SSL_write (client->ssl,
          (const char *)buf + pos, len - pos);
    } else {
      #ifdef __APPLE__
      written = send (client->fd,
          (const char *)buf + pos, len - pos, 0);
      #else
      written = send (client->fd,
          (const char *)buf + pos, len - pos, MSG_NOSIGNAL);
      #endif
    }
    if (written < 0) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      debug ("unable to send: %s", strerror (errno));
      return written;
    }
    if (written == 0)
      break;
    pos += written;
  }
  return pos;
}

static void
print_ssl_errors ()
{
  char tmp[4096];
  gint error;
  while ((error = ERR_get_error ()) != 0) {
    memset (tmp, 0, sizeof (tmp));
    ERR_error_string_n (error, tmp, sizeof (tmp) - 1);
    warning ("ssl-error: %s", tmp);
  }
}

gboolean
client_add_incoming_ssl (Client * client, gchar * cert, gchar * key)
{
  client->ssl_ctx = SSL_CTX_new (SSLv23_server_method());
  //SSL_CTX_set_options (client->ssl_ctx, SSL_OP_ALL);
  //SSL_CTX_set_default_verify_paths (client->ssl_ctx);

  if (strlen (cert) > 0 ) {
    BIO * cert_bio = BIO_new_mem_buf (cert, -1);
    X509 * cert_x509 = PEM_read_bio_X509 (cert_bio, NULL, 0, NULL);
    if (cert_x509) {
      if (SSL_CTX_use_certificate (client->ssl_ctx, cert_x509) <= 0) {
        warning ("did not like the certificate: %s", cert);
        print_ssl_errors ();
        return FALSE;
      }
      X509_free (cert_x509);
    }
    BIO_free (cert_bio);
  }

  if (strlen (key) > 0) {
    BIO * key_bio = BIO_new_mem_buf (key, -1);
    EVP_PKEY * key_evp = PEM_read_bio_PrivateKey (key_bio, NULL, 0, NULL);
    if (key_evp) {
      if (SSL_CTX_use_PrivateKey (client->ssl_ctx, key_evp) <= 0) {
        warning ("did not like the key: %s", key);
        print_ssl_errors ();
        return FALSE;
      }
      EVP_PKEY_free (key_evp);
    }
    BIO_free (key_bio);
  }

  SSL_CTX_set_verify (client->ssl_ctx, SSL_VERIFY_NONE, NULL);

  client->ssl = SSL_new (client->ssl_ctx);
  SSL_set_fd (client->ssl, client->fd);

  if (SSL_accept (client->ssl) < 0) {
    warning ("Unable to establish ssl-connection");
    print_ssl_errors ();
    return FALSE;
  }

  return TRUE;
}

Client *
client_new (gint fd, Connections * connections, GObject * server,
    gboolean use_ssl, gint stream_id, gint chunk_size)
{
  Client * client = g_new0 (Client, 1);

  client->fd = fd;
  client->connections = connections;
  client->server = server;
  client->use_ssl = use_ssl;
  client->msg_stream_id = stream_id;
  client->chunk_size = chunk_size;
  debug ("Chunk Size: %d, Stream ID:%d\n", chunk_size, stream_id);

  client->window_size = DEFAULT_WINDOW_SIZE;

  for (int i = 0; i < 64; ++i) {
    client->messages[i].timestamp = 0;
    client->messages[i].abs_timestamp = 0;
    client->messages[i].len = 0;
    client->messages[i].buf = g_byte_array_new ();
  }

  client->send_queue = g_byte_array_new ();
  client->buf = g_byte_array_new ();

  return client;
}

void
client_free (Client * client)
{
  for (int i = 0; i < 64; ++i) {
    g_byte_array_free (client->messages[i].buf, TRUE);
  }

  g_byte_array_free (client->buf, TRUE);
  g_byte_array_free (client->send_queue, TRUE);

  if (client->metadata)
    gst_structure_free (client->metadata);
  g_free (client->path);
  g_free (client->dialout_path);

  /* ssl */
  if (client->ssl_ctx)
    SSL_CTX_free (client->ssl_ctx);
  if (client->ssl)
    SSL_free (client->ssl);

  g_free (client);
}
