/* PexRTMPServer
 * Copyright (C) 2011 Janne Kulmala <janne.t.kulmala@iki.fi>
 * Copyright (C) 2019 Pexip
 *  @author: Havard Graff <havard@pexip.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
#include "client.h"
#include "rtmp.h"
#include "auth.h"

#include "utils/amf.h"
#include "utils/flv.h"
#include "utils/parse.h"
#include "utils/tcp.h"

#include <string.h>

#ifdef G_OS_WIN32
#  include <Ws2ipdef.h>
#  include <Ws2tcpip.h>
#  include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#  define MSG_NOSIGNAL 0x4000
#else
#  include <arpa/inet.h>
#endif

#ifdef HAVE_OPENSSL
#  include <openssl/err.h>
#endif

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

/* This is the Chunk Message Header FIXME: rename? */
#pragma pack(push)  /* push current alignment to stack */
#pragma pack(1)     /* set alignment to 1 byte boundary */
typedef struct
{
  guint8 flags;
  guint8 timestamp[3];
  guint8 msg_len[3];
  guint8 msg_type_id;
  guint32 msg_stream_id; /* Note, this is little-endian while others are BE */
} RTMPHeader;

#pragma pack(pop)   /* restore original alignment from stack */

gboolean
client_add_connection (Client * client, gboolean publisher)
{
  gboolean ret = TRUE;
  if (publisher) {
    ret = connections_add_publisher (client->connections, client, client->path);
  } else {
    connections_add_subscriber (client->connections, client, client->path);
  }
  return ret;
}

static gboolean
client_notify_connection (Client * client)
{
  return client->notify_connection (client->server, client);
}

static void
client_write_extended_timestamp (Client * client, guint32 timestamp)
{
  guint8 ext_timestamp[4];
  GST_WRITE_UINT32_BE (ext_timestamp, timestamp);
  client->send_queue = g_byte_array_append (client->send_queue,
      ext_timestamp, 4);
}

static void
client_direct_send (Client * client,
    guint8 id, GByteArray * buf, guint32 timestamp)
{
  if (id != MSG_AUDIO && id != MSG_VIDEO && id != MSG_NOTIFY)
    return;

  if (client->write_flv_header) {
    gst_buffer_queue_push (client->flv_queue, flv_generate_header ());
    client->write_flv_header = FALSE;
  }

  gst_buffer_queue_push (client->flv_queue,
      flv_generate_tag (buf->data, buf->len, id, timestamp));
}

static PexRtmpServerStatus
client_rtmp_send (Client * client, guint8 msg_type_id, guint32 msg_stream_id,
    GByteArray * buf, guint32 abs_timestamp, guint8 chunk_stream_id)
{
  if (client->direct) {
    client_direct_send (client, msg_type_id, buf, abs_timestamp);
    return PEX_RTMP_SERVER_STATUS_OK;
  }
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;

  gint fmt = 0;
  guint32 timestamp = abs_timestamp;
  const guint msg_len = buf->len;
  gint use_ext_timestamp = timestamp >= EXT_TIMESTAMP_LIMIT;

/* FIXME: disable pending investigation on why YouTube fails */
#if 0
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

  RTMPHeader header;
  guint header_len = CHUNK_MSG_HEADER_LENGTH[fmt];
  chunk_stream_id &= 0x3f;
  header.flags = chunk_stream_id | (fmt << 6);
  header.msg_type_id = msg_type_id;
  if (use_ext_timestamp) {
    GST_WRITE_UINT24_BE (header.timestamp, EXT_TIMESTAMP_LIMIT);
  } else {
    GST_WRITE_UINT24_BE (header.timestamp, timestamp);
  }
  GST_WRITE_UINT24_BE (header.msg_len, msg_len);
  header.msg_stream_id = msg_stream_id;
  GST_LOG_OBJECT (client->server, "Sending packet with:\n"
      "format:%d, chunk_stream_id:%u, timestamp:%u, msg_len:%u, msg_type_id:%u, msg_stream_id:%u",
      fmt, chunk_stream_id, timestamp, msg_len, msg_type_id, msg_stream_id);
  client->send_queue = g_byte_array_append (client->send_queue,
      (guint8 *) & header, header_len);

  if (use_ext_timestamp)
    client_write_extended_timestamp (client, timestamp);

  guint pos = 0;
  while (pos < msg_len) {
    if (pos) {
      guint8 flags = chunk_stream_id | (3 << 6);
      client->send_queue = g_byte_array_append (client->send_queue, &flags, 1);

      /* we rewrite the extended timestamp for multiple chunks in a message, like Flash does */
      if (use_ext_timestamp)
        client_write_extended_timestamp (client, timestamp);
    }

    guint chunk = msg_len - pos;
    if (chunk > client->send_chunk_size)
      chunk = client->send_chunk_size;
    client->send_queue = g_byte_array_append (client->send_queue,
        &buf->data[pos], chunk);

    ret = client_send (client);
    if (ret != PEX_RTMP_SERVER_STATUS_OK)
      break;

    pos += chunk;
    GST_LOG_OBJECT (client->server, "Sent chunk of size %u (%u / %u)",
        chunk, pos, msg_len);
  }

  return ret;
}

static PexRtmpServerStatus
client_send_reply (Client * client, double txid, const GValue * reply,
    const GValue * status)
{
  if (txid <= 0.0)
    return PEX_RTMP_SERVER_STATUS_OK; /* FIXME: OK? */

  AmfEnc *invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "_result");
  amf_enc_write_double (invoke, txid);
  amf_enc_write_value (invoke, reply);
  amf_enc_write_value (invoke, status);

  PexRtmpServerStatus ret = client_rtmp_send (client, MSG_INVOKE,
      MSG_STREAM_ID_CONTROL, invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
  amf_enc_free (invoke);
  return ret;
}

static PexRtmpServerStatus
client_send_error (Client * client, double txid, const GstStructure * status)
{
  if (txid <= 0.0)
    return PEX_RTMP_SERVER_STATUS_OK; /* FIXME: OK? */

  AmfEnc *invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "_error");
  amf_enc_write_double (invoke, txid);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  PexRtmpServerStatus ret = client_rtmp_send (client, MSG_INVOKE,
      MSG_STREAM_ID_CONTROL, invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
  amf_enc_free (invoke);
  return ret;
}

static PexRtmpServerStatus
client_set_chunk_size (Client * client, gint chunk_size)
{
  GST_DEBUG_OBJECT (client->server, "Setting new send-chunk-size to %d",
      chunk_size);

  AmfEnc *invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (chunk_size));
  PexRtmpServerStatus ret = client_rtmp_send (client, MSG_SET_CHUNK,
      MSG_STREAM_ID_CONTROL, invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);
  client->send_chunk_size = chunk_size;
  return ret;
}

/* Result messages come from a server to the client,
   but in the dial-out case we are both! */
static PexRtmpServerStatus
client_handle_subscribe_result (Client * client, gint txid, AmfDec * dec)
{
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;

  if (txid == 1) {
    GST_DEBUG_OBJECT (client->server,
        "Sending releaseStream + FCPublish + createStream");
    AmfEnc *invoke;
    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "releaseStream");
    amf_enc_write_double (invoke, 2.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    ret = client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);
    if (ret != PEX_RTMP_SERVER_STATUS_OK)
      goto done;

    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "FCPublish");
    amf_enc_write_double (invoke, 3.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    ret = client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);
    if (ret != PEX_RTMP_SERVER_STATUS_OK)
      goto done;

    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "createStream");
    amf_enc_write_double (invoke, 4.0);
    amf_enc_write_null (invoke);
    ret = client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);
    if (ret != PEX_RTMP_SERVER_STATUS_OK)
      goto done;

  } else if (txid == 4) {
    GValue *reply = amf_dec_load (dec);
    GValue *status = amf_dec_load (dec);
    client->msg_stream_id = (guint) g_value_get_double (status);
    GST_DEBUG_OBJECT (client->server, "Got message stream id %d",
        client->msg_stream_id);
    g_value_unset (reply);
    g_value_unset (status);
    g_free (reply);
    g_free (status);

    GST_DEBUG_OBJECT (client->server, "Sending publish to %s",
        client->dialout_path);
    AmfEnc *invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "publish");
    amf_enc_write_double (invoke, 0.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    amf_enc_write_string (invoke, "live");
    ret = client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    amf_enc_free (invoke);
  }

done:
  return ret;
}

static PexRtmpServerStatus
client_handle_publish_result (Client * client, gint txid, AmfDec * dec)
{
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;

  if (txid == 1) {
    client_set_chunk_size (client, client->chunk_size);

    GST_DEBUG_OBJECT (client->server, "Sending createStream");
    AmfEnc *invoke;
    invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "createStream");
    amf_enc_write_double (invoke, 2.0);
    amf_enc_write_null (invoke);
    ret = client_rtmp_send (client, MSG_INVOKE, MSG_STREAM_ID_CONTROL,
        invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
    amf_enc_free (invoke);
  } else if (txid == 2) {
    GValue *reply = amf_dec_load (dec);
    GValue *status = amf_dec_load (dec);
    client->msg_stream_id = (guint) g_value_get_double (status);
    GST_DEBUG_OBJECT (client->server, "Got message stream id %d",
        client->msg_stream_id);
    g_value_unset (reply);
    g_value_unset (status);
    g_free (reply);
    g_free (status);

    GST_DEBUG_OBJECT (client->server, "Sending play to %s",
        client->dialout_path);
    AmfEnc *invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "play");
    amf_enc_write_double (invoke, 0.0);
    amf_enc_write_null (invoke);
    amf_enc_write_string (invoke, client->dialout_path);
    ret = client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    amf_enc_free (invoke);
  }

  return ret;
}

static PexRtmpServerStatus
client_handle_result (Client * client, gint txid, AmfDec * dec)
{
  /* we won't handle this unless we are dialing out to a path */
  if (client->dialout_path == NULL)
    return PEX_RTMP_SERVER_STATUS_OK;

  GST_DEBUG_OBJECT (client->server, "Handling result for txid %d", txid);
  if (!client->publisher) {
    return client_handle_subscribe_result (client, txid, dec);
  } else {
    return client_handle_publish_result (client, txid, dec);
  }
}


static PexRtmpServerStatus
client_handle_error (Client * client, gint txid, AmfDec * dec)
{
  /* we won't handle this unless we are dialing out to a path */
  if (client->dialout_path == NULL)
    return PEX_RTMP_SERVER_STATUS_OK;

  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_ERROR;

  g_free (amf_dec_load (dec));  /* NULL */
  GstStructure *object = amf_dec_load_object (dec);

  const gchar *code = gst_structure_get_string (object, "code");
  gchar *object_str = gst_structure_to_string (object);
  GST_DEBUG_OBJECT (client->server, "Handling error for txid %d with object %s",
      txid, object_str);
  g_free (object_str);

  if (g_strcmp0 (code, "NetConnection.Connect.Rejected") == 0) {
    const gchar *description = gst_structure_get_string (object, "description");
    ret = PEX_RTMP_SERVER_STATUS_NEED_AUTH;

    if (g_strrstr (description, "authmod=adobe")) {
      if (g_strrstr (description, "code=403 need auth")) {
        g_free (client->auth_token);
        if (client->username) {
          client->auth_token = g_strdup_printf ("?authmod=adobe&user=%s",
              client->username);
          client->retry_connection = TRUE;
          ret = PEX_RTMP_SERVER_STATUS_OK;
        }
      } else {
        gchar *auth_str = g_strrstr (description, "?reason=needauth");
        if (auth_str) {
          g_free (client->auth_token);
          if (client->username && client->password) {
            client->auth_token = auth_get_token (auth_str,
                client->username, client->password);
            client->retry_connection = TRUE;
            ret = PEX_RTMP_SERVER_STATUS_OK;
          }
        }
      }
    }
  }

  gst_structure_free (object);
  return ret;
}

static PexRtmpServerStatus
client_handle_onstatus (Client * client, AmfDec * dec, gint stream_id)
{
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;

  /* we won't handle this unless we are dialing out to a path */
  if (client->dialout_path == NULL)
    return PEX_RTMP_SERVER_STATUS_OK;

  g_free (amf_dec_load (dec));  /* NULL */
  GstStructure *object = amf_dec_load_object (dec);

  const gchar *code = gst_structure_get_string (object, "code");
  GST_DEBUG_OBJECT (client->server, "onStatus - code: %s", code);
  if (code && g_strcmp0 (code, "NetStream.Play.Start") == 0) {
    /* make the client a publisher on the local server */
    if (!client_add_connection (client, TRUE)) {
      ret = PEX_RTMP_SERVER_STATUS_MULTIPLE_PUBLISHERS;
      goto done;
    }
    client_notify_connection (client);
  } else if (code && g_strcmp0 (code, "NetStream.Publish.Start") == 0) {
    /* make the client a subscriber on the local server */
    client_add_connection (client, FALSE);

    GstStructure *meta = gst_structure_new ("object",
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
    AmfEnc *invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "@setDataFrame");
    amf_enc_write_string (invoke, "onMetaData");
    amf_enc_write_object (invoke, meta);
    ret = client_rtmp_send (client, MSG_NOTIFY, stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    amf_enc_free (invoke);
    gst_structure_free (meta);
    if (ret != PEX_RTMP_SERVER_STATUS_OK)
      goto done;

    client_notify_connection (client);
  }

done:
  gst_structure_free (object);
  return ret;
}

static PexRtmpServerStatus
client_do_connect (Client * client)
{
  GST_DEBUG_OBJECT (client->server, "connecting to: %s with path: %s",
      client->tcUrl, client->path);

  gchar *app;
  gchar *tcUrl;

  if (client->auth_token) {
    app = g_strdup_printf ("%s%s", client->app, client->auth_token);
    tcUrl = g_strdup_printf ("%s%s", client->tcUrl, client->auth_token);
  } else {
    app = g_strdup (client->app);
    tcUrl = g_strdup (client->tcUrl);
  }

  /* send connect */
  GstStructure *status = gst_structure_new ("object",
      "app", G_TYPE_STRING, app,
      "type", G_TYPE_STRING, "nonprivate",
      "flashVer", G_TYPE_STRING, "FMLE/3.0 (Pexip RTMP Server)",
      "tcUrl", G_TYPE_STRING, tcUrl,
      "fpad", G_TYPE_BOOLEAN, TRUE,
      "swfUrl", G_TYPE_STRING, client->tcUrl,
      NULL);

  g_free (app);
  g_free (tcUrl);

//      "fpad", G_TYPE_BOOLEAN, TRUE, /* we are doing proxying */
//      "audioCodecs", G_TYPE_DOUBLE, (gdouble)(SUPPORT_SND_AAC | SUPPORT_SND_SPEEX),
//      "videoCodecs", G_TYPE_DOUBLE, (gdouble)SUPPORT_VID_H264,
//      "videoFunctions", G_TYPE_DOUBLE, 0.0, /* We can't do seek */
//      "objectEncoding", G_TYPE_DOUBLE, 0.0, /* AMF0 */

  AmfEnc *invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "connect");
  amf_enc_write_double (invoke, 1.0);
  amf_enc_write_object (invoke, status);

  PexRtmpServerStatus ret = client_rtmp_send (client, MSG_INVOKE,
      MSG_STREAM_ID_CONTROL, invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
  amf_enc_free (invoke);
  gst_structure_free (status);

  return ret;
}

static PexRtmpServerStatus
client_handle_connect (Client * client, double txid, AmfDec * dec)
{
  AmfEnc *invoke;
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;
  GstStructure *params = amf_dec_load_object (dec);

  client->app = g_strdup (gst_structure_get_string (params, "app"));
  gchar *params_str = gst_structure_to_string (params);
  GST_INFO_OBJECT (client->server, "connect: %s", params_str);
  g_free (params_str);

  /* a bit hackish, we use the presence of "type" to determine if this is
     a publisher */
  const gchar *type = gst_structure_get_string (params, "type");

  if (type && client->username && client->password) {
    gchar *description;
    gboolean auth_ok = auth_verify (client->app, client->username,
        client->password, client->salt, client->opaque, &description);
    if (!auth_ok) {
      GstStructure *status = gst_structure_new ("object",
          "level", G_TYPE_STRING, "error",
          "code", G_TYPE_STRING, "NetConnection.Connect.Rejected",
          "description", G_TYPE_STRING, description,
          NULL);
      client_send_error (client, txid, status);
      gst_structure_free (status);
      g_free (description);
      ret = PEX_RTMP_SERVER_STATUS_AUTH_REJECTED;
      goto done;
    }
  }

  /* Send win ack size */
  invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (client->window_size));
  ret = client_rtmp_send (client, MSG_WINDOW_ACK_SIZE, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    goto done;

  /* Send set peer bandwidth */
  invoke = amf_enc_new ();
  amf_enc_add_int (invoke, htonl (5000000));
  amf_enc_add_char (invoke, AMF_DYNAMIC);
  ret = client_rtmp_send (client, MSG_SET_PEER_BW, MSG_STREAM_ID_CONTROL,
      invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    goto done;

  /* Set sending chunk size */
  client_set_chunk_size (client, client->chunk_size);

  GValue version = G_VALUE_INIT;
  g_value_init (&version, GST_TYPE_STRUCTURE);
  GstStructure *version_s = gst_structure_new ("object",
      "fmsVer", G_TYPE_STRING, "FMS/3,5,3,824",
      "capabilities", G_TYPE_DOUBLE, 127.0,
      "mode", G_TYPE_DOUBLE, 1.0,
      NULL);
  gst_value_set_structure (&version, version_s);
  gst_structure_free (version_s);

  GValue status = G_VALUE_INIT;
  g_value_init (&status, GST_TYPE_STRUCTURE);
  GstStructure *status_s = gst_structure_new ("object",
      "level", G_TYPE_STRING, "status",
      "code", G_TYPE_STRING, "NetConnection.Connect.Success",
      "description", G_TYPE_STRING, "Connection succeeded.",
      "objectEncoding", G_TYPE_DOUBLE, 0.0,
      NULL);
  gst_value_set_structure (&status, status_s);
  gst_structure_free (status_s);

  ret = client_send_reply (client, txid, &version, &status);
  g_value_unset (&version);
  g_value_unset (&status);

done:
  gst_structure_free (params);

  return ret;
}

static PexRtmpServerStatus
client_handle_fcpublish (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));  /* NULL */

  gchar *path = amf_dec_load_string (dec);
  GST_DEBUG_OBJECT (client->server, "fcpublish %s", path);
  if (path == NULL)
    return PEX_RTMP_SERVER_STATUS_INVALID_FCPUBLISH;

  GstStructure *status = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetStream.Publish.Start",
      "description", G_TYPE_STRING, path,
      NULL);
  g_free (path);

  AmfEnc *invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onFCPublish");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  PexRtmpServerStatus ret = client_rtmp_send (client, MSG_INVOKE,
      MSG_STREAM_ID_CONTROL, invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (invoke);
  gst_structure_free (status);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    return ret;

  return client_send_reply (client, txid, NULL, NULL);
}

static PexRtmpServerStatus
client_handle_createstream (Client * client, double txid)
{
  GValue stream_id = G_VALUE_INIT;
  g_value_init (&stream_id, G_TYPE_DOUBLE);
  g_value_set_double (&stream_id, (gdouble) client->msg_stream_id);
  return client_send_reply (client, txid, NULL, &stream_id);
}

static PexRtmpServerStatus
client_handle_publish (Client * client, double txid, AmfDec * dec)
{
  PexRtmpServerStatus ret;

  g_free (amf_dec_load (dec));  /* NULL */
  gchar *path = amf_dec_load_string (dec);
  GST_DEBUG_OBJECT (client->server, "publish %s", path);
  if (path == NULL)
    return PEX_RTMP_SERVER_STATUS_INVALID_PUBLISH;

  client->publisher = TRUE;
  g_free (client->path);
  client->path = path;

  gboolean reject_publish = client_notify_connection (client);
  if (reject_publish) {
    GST_DEBUG_OBJECT (client->server,
        "Not publishing due to being rejected");
    return PEX_RTMP_SERVER_STATUS_PUBLISH_REJECTED;
  }
  if (!client_add_connection (client, TRUE)) {
    return PEX_RTMP_SERVER_STATUS_MULTIPLE_PUBLISHERS;
  }
  GST_DEBUG_OBJECT (client->server, "publisher connected.");

  /* StreamBegin */
  AmfEnc *control = amf_enc_new ();
  amf_enc_add_short (control, htons (CONTROL_CLEAR_STREAM));
  amf_enc_add_int (control, htonl (client->msg_stream_id));
  ret = client_rtmp_send (client, MSG_USER_CONTROL, MSG_STREAM_ID_CONTROL,
      control->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (control);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    return ret;

  /* _result for publish */
  GstStructure *status = gst_structure_new ("object",
      "level", G_TYPE_STRING, "status",
      "code", G_TYPE_STRING, "NetStream.Publish.Start",
      "description", G_TYPE_STRING, "Stream is now published.",
      "details", G_TYPE_STRING, path,
      NULL);
  AmfEnc *invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onStatus");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  ret = client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_RESULT);
  amf_enc_free (invoke);
  gst_structure_free (status);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    return ret;

  return client_send_reply (client, txid, NULL, NULL);
}

static PexRtmpServerStatus
client_start_playback (Client * client)
{
  PexRtmpServerStatus ret;

  /* StreamBegin */
  AmfEnc *control = amf_enc_new ();
  amf_enc_add_short (control, htons (CONTROL_CLEAR_STREAM));
  amf_enc_add_int (control, htonl (client->msg_stream_id));
  ret = client_rtmp_send (client, MSG_USER_CONTROL, MSG_STREAM_ID_CONTROL,
      control->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (control);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    goto done;

  GstStructure *status = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetStream.Play.Reset",
      "description", G_TYPE_STRING, "Resetting and playing stream.",
      "level", G_TYPE_STRING, "status",
      NULL);
  AmfEnc *invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onStatus");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);
  ret = client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);
  gst_structure_free (status);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    goto done;

  status = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetStream.Play.Start",
      "description", G_TYPE_STRING, "Started playing.",
      "level", G_TYPE_STRING, "status", NULL);
  invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onStatus");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);
  ret = client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);
  gst_structure_free (status);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    goto done;

  invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "|RtmpSampleAccess");
  amf_enc_write_bool (invoke, TRUE);
  amf_enc_write_bool (invoke, TRUE);
  ret = client_rtmp_send (client, MSG_NOTIFY, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    goto done;

  client->playing = TRUE;
  client->ready = FALSE;
  client_add_connection (client, FALSE);

  /* send pexip metadata to the client */
  GstStructure *metadata = gst_structure_new ("metadata",
      "Server", G_TYPE_STRING, "Pexip RTMP Server", NULL);
  GST_DEBUG_OBJECT (client->server, "(%s) METADATA %" GST_PTR_FORMAT,
      client->path, metadata);
  invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onMetaData");
  amf_enc_write_object (invoke, metadata);
  ret = client_rtmp_send (client, MSG_NOTIFY, client->msg_stream_id,
      invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
  amf_enc_free (invoke);
  gst_structure_free (metadata);

done:
  return ret;
}

static PexRtmpServerStatus
client_handle_play (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));  /* NULL */
  gchar *path = amf_dec_load_string (dec);
  if (path == NULL)
    return PEX_RTMP_SERVER_STATUS_INVALID_PLAY;

  g_free (client->path);
  client->path = path;

  gboolean reject_play = client_notify_connection (client);
  if (reject_play) {
    GST_DEBUG_OBJECT (client->server,
        "%p Not playing due to being rejecte", client);
    return PEX_RTMP_SERVER_STATUS_PLAY_REJECTED;
  }
  GST_DEBUG_OBJECT (client->server, "client %p got play for path: %s", client,
      path);

  PexRtmpServerStatus ret = client_start_playback (client);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    return ret;

  return client_send_reply (client, txid, NULL, NULL);
}

static PexRtmpServerStatus
client_handle_play2 (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));  /* NULL */

  GstStructure *params = amf_dec_load_object (dec);
  const gchar *path = gst_structure_get_string (params, "streamName");
  GST_DEBUG_OBJECT (client->server, "play2 %s", path);
  gst_structure_free (params);

  if (path == NULL)
    return PEX_RTMP_SERVER_STATUS_INVALID_PLAY2;

  PexRtmpServerStatus ret = client_start_playback (client);
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    return ret;

  return client_send_reply (client, txid, NULL, NULL);
}

static PexRtmpServerStatus
client_handle_pause (Client * client, double txid, AmfDec * dec)
{
  PexRtmpServerStatus ret;
  g_free (amf_dec_load (dec));  /* NULL */

  gboolean paused;
  if (amf_dec_load_boolean (dec, &paused) && paused) {
    GST_DEBUG_OBJECT (client->server, "pausing");

    GstStructure *status = gst_structure_new ("object",
        "code", G_TYPE_STRING, "NetStream.Pause.Notify",
        "description", G_TYPE_STRING, "Pausing.",
        "level", G_TYPE_STRING, "status",
        NULL);
    AmfEnc *invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "onStatus");
    amf_enc_write_double (invoke, 0.0);
    amf_enc_write_null (invoke);
    amf_enc_write_object (invoke, status);

    ret = client_rtmp_send (client, MSG_INVOKE, client->msg_stream_id,
        invoke->buf, 0, CHUNK_STREAM_ID_STREAM);
    client->playing = FALSE;
  } else {
    ret = client_start_playback (client);
  }

  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    return ret;

  return client_send_reply (client, txid, NULL, NULL);
}

static void
client_handle_setdataframe (Client * client, AmfDec * dec)
{
  if (!client->publisher) {
    GST_WARNING_OBJECT (client->server, "not a publisher");
    return;
  }

  gchar *type = amf_dec_load_string (dec);
  if (type && strcmp (type, "onMetaData") != 0) {
    GST_WARNING_OBJECT (client->server, "can only set metadata");
  }
  g_free (type);

  if (client->metadata)
    gst_structure_free (client->metadata);
  client->metadata = amf_dec_load_object (dec);
  GST_DEBUG_OBJECT (client->server, "(%s) METADATA %" GST_PTR_FORMAT,
      client->path, client->metadata);
}

static PexRtmpServerStatus
client_handle_user_control (Client * client, const guint32 timestamp)
{
  AmfEnc *enc = amf_enc_new ();
  guint16 ping_response_id = 7;
  amf_enc_add_short (enc, htons (ping_response_id));
  amf_enc_add_int (enc, htonl (timestamp));
  PexRtmpServerStatus ret = client_rtmp_send (client, MSG_USER_CONTROL,
      MSG_STREAM_ID_CONTROL, enc->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (enc);
  return ret;
}

static PexRtmpServerStatus
client_handle_invoke (Client * client, const RTMPMessage * msg, AmfDec * dec)
{
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;
  gchar *method = amf_dec_load_string (dec);
  gdouble txid;

  if (method == NULL)
    return PEX_RTMP_SERVER_STATUS_INVALID_INVOKE;

  if (!amf_dec_load_number (dec, &txid))
    return PEX_RTMP_SERVER_STATUS_INVALID_INVOKE;

  GST_DEBUG_OBJECT (client->server,
      "%p: invoked %s with txid %lf for Stream Id: %d ", client, method, txid,
      msg->msg_stream_id);

  if (strcmp (method, "onStatus") == 0) {
    ret = client_handle_onstatus (client, dec, msg->msg_stream_id);
  } else if (msg->msg_stream_id == MSG_STREAM_ID_CONTROL) {
    if (strcmp (method, "connect") == 0) {
      ret = client_handle_connect (client, txid, dec);
    } else if (strcmp (method, "FCPublish") == 0) {
      ret = client_handle_fcpublish (client, txid, dec);
    } else if (strcmp (method, "createStream") == 0) {
      ret = client_handle_createstream (client, txid);
    } else if (strcmp (method, "_result") == 0) {
      ret = client_handle_result (client, (gint) txid, dec);
    } else if (strcmp (method, "_error") == 0) {
      ret = client_handle_error (client, (gint) txid, dec);
    }
  } else if (msg->msg_stream_id == client->msg_stream_id) {
    if (strcmp (method, "publish") == 0) {
      ret = client_handle_publish (client, txid, dec);
    } else if (strcmp (method, "play") == 0) {
      ret = client_handle_play (client, txid, dec);
    } else if (strcmp (method, "play2") == 0) {
      ret = client_handle_play2 (client, txid, dec);
    } else if (strcmp (method, "pause") == 0) {
      ret = client_handle_pause (client, txid, dec);
    }
  }

  g_free (method);
  return ret;
}

gboolean
client_window_size_reached (Client * client)
{
  return (client->bytes_received_since_ack >= client->window_size);
}

static PexRtmpServerStatus
client_send_ack (Client * client)
{
  AmfEnc *enc = amf_enc_new ();
  amf_enc_add_int (enc, htonl (client->total_bytes_received));
  client->bytes_received_since_ack = 0;
  PexRtmpServerStatus ret = client_rtmp_send (client, MSG_ACK,
      MSG_STREAM_ID_CONTROL, enc->buf, 0, CHUNK_STREAM_ID_CONTROL);
  amf_enc_free (enc);
  return ret;
}

PexRtmpServerStatus
client_handle_message (Client * client, RTMPMessage * msg)
{
  GST_LOG_OBJECT (client->server, "RTMP message %02x, len %u, abs-timestamp %u",
      msg->type, msg->len, msg->abs_timestamp);
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;

  /* send window-size ACK if we have reached it */
  client->total_bytes_received += msg->len;
  if (client->publisher) {
    client->bytes_received_since_ack += msg->len;
    if (client_window_size_reached (client))
      ret = client_send_ack (client);
  }
  if (ret != PEX_RTMP_SERVER_STATUS_OK)
    return ret;

  guint pos = 0;
  switch (msg->type) {
    case MSG_ACK:
      if (pos + 4 > msg->buf->len) {
        GST_DEBUG_OBJECT (client->server, "Not enough data");
        return PEX_RTMP_SERVER_STATUS_INVALID_MSG;
      }
      break;

    case MSG_SET_CHUNK:
      if (pos + 4 > msg->buf->len) {
        GST_DEBUG_OBJECT (client->server, "Not enough data");
        return PEX_RTMP_SERVER_STATUS_INVALID_MSG;
      }
      client->recv_chunk_size = GST_READ_UINT32_BE (&msg->buf->data[pos]);
      GST_DEBUG_OBJECT (client->server, "receive chunk size set to %d",
          client->recv_chunk_size);
      break;

    case MSG_USER_CONTROL:
    {
      guint16 method = GST_READ_UINT16_BE (&msg->buf->data[pos]);
      if (method == 6) {
        guint32 timestamp = GST_READ_UINT32_BE (&msg->buf->data[pos + 2]);
        ret = client_handle_user_control (client, timestamp);
      }
      break;
    }

    case MSG_WINDOW_ACK_SIZE:
    {
      client->window_size = GST_READ_UINT32_BE (&msg->buf->data[pos]);
      GST_DEBUG_OBJECT (client->server, "%s window size set to %u",
          client->path, client->window_size);
      break;
    }

    case MSG_SET_PEER_BW:
    {
      client->window_size = GST_READ_UINT32_BE (&msg->buf->data[pos]);
      GST_DEBUG_OBJECT (client->server,
          "%s Got Set Peer BW msg, window size set to %u", client->path,
          client->window_size);

      // Send back the expected Window Ack Msg
      AmfEnc *invoke = amf_enc_new ();
      amf_enc_add_int (invoke, htonl (client->window_size));
      ret = client_rtmp_send (client, MSG_WINDOW_ACK_SIZE, MSG_STREAM_ID_CONTROL,
          invoke->buf, 0, CHUNK_STREAM_ID_CONTROL);
      amf_enc_free (invoke);
      break;
    }

    case MSG_INVOKE:
    {
      AmfDec *dec = amf_dec_new (msg->buf, 0);
      ret = client_handle_invoke (client, msg, dec);
      amf_dec_free (dec);
      break;
    }

    case MSG_INVOKE3:
    {
      AmfDec *dec = amf_dec_new (msg->buf, 1);
      ret = client_handle_invoke (client, msg, dec);
      amf_dec_free (dec);
      break;
    }

    case MSG_NOTIFY:
    {
      AmfDec *dec = amf_dec_new (msg->buf, 0);
      gchar *type = amf_dec_load_string (dec);
      GST_DEBUG_OBJECT (client->server, "notify %s", type);
      if (msg->msg_stream_id == client->msg_stream_id) {
        if (type && strcmp (type, "@setDataFrame") == 0) {
          client_handle_setdataframe (client, dec);
        }
      }
      g_free (type);
      amf_dec_free (dec);
      break;
    }

    case MSG_DATA:
    {
      AmfDec *dec = amf_dec_new (msg->buf, 1);
      gchar *type = amf_dec_load_string (dec);
      GST_DEBUG_OBJECT (client->server, "data %s", type);
      if (msg->msg_stream_id == client->msg_stream_id) {
        if (type && strcmp (type, "@setDataFrame") == 0) {
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
        return PEX_RTMP_SERVER_STATUS_INVALID_MSG;
      }
      GSList *subscribers =
          connections_get_subscribers (client->connections, client->path);
      for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
        Client *subscriber = (Client *) walk->data;

/* FIXME: this is the best way, can we make it so ?
        client_rtmp_send (subscriber, MSG_AUDIO, subscriber->msg_stream_id,
            msg->buf, msg->timestamp, msg->fmt, CHUNK_STREAM_ID_CONTROL);
*/
        ret = client_rtmp_send (subscriber, MSG_AUDIO,
            subscriber->msg_stream_id, msg->buf,
            msg->abs_timestamp, CHUNK_STREAM_ID_STREAM);
      }
      break;


    case MSG_VIDEO:
    {
      if (!client->publisher) {
        GST_DEBUG_OBJECT (client->server, "not a publisher");
        return PEX_RTMP_SERVER_STATUS_INVALID_MSG;
      }
      guint8 flags = msg->buf->data[0];
      GSList *subscribers =
          connections_get_subscribers (client->connections, client->path);
      gboolean stored_packet = FALSE;
      if (!client->video_codec_data) {
        stored_packet = TRUE;
        GByteArray *codec_data = g_byte_array_new ();
        g_byte_array_append (codec_data, msg->buf->data, msg->buf->len);
        client->video_codec_data = codec_data;
      }
      for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
        Client *subscriber = (Client *) walk->data;

        if (!subscriber->ready) {
          ret = client_rtmp_send (subscriber, MSG_VIDEO,
              subscriber->msg_stream_id, client->video_codec_data,
              msg->abs_timestamp, CHUNK_STREAM_ID_STREAM);
        }
        if (flags >> 4 == FLV_KEY_FRAME && !subscriber->ready) {
          subscriber->ready = TRUE;
          if (!stored_packet) {
            ret = client_rtmp_send (subscriber, MSG_VIDEO,
                subscriber->msg_stream_id, msg->buf,
                msg->abs_timestamp, CHUNK_STREAM_ID_STREAM);
          }
        }
        if (subscriber->ready) {
          ret = client_rtmp_send (subscriber, MSG_VIDEO,
              subscriber->msg_stream_id, msg->buf,
              msg->abs_timestamp, CHUNK_STREAM_ID_STREAM);
        }
      }
      break;
    }

    case MSG_FLASH_VIDEO:
      GST_WARNING_OBJECT (client->server, "streaming FLV not supported");
      ret = PEX_RTMP_SERVER_STATUS_NOT_SUPPORTED;
      break;

    default:
      GST_DEBUG_OBJECT (client->server, "unhandled message: %02x", msg->type);
      gst_util_dump_mem (msg->buf->data, msg->buf->len);
      break;
  }

  return ret;
}

static RTMPMessage *
rtmp_message_new ()
{
  RTMPMessage *msg = g_new0 (RTMPMessage, 1);
  msg->buf = g_byte_array_new ();
  return msg;
}

static void
rtmp_message_free (RTMPMessage * msg)
{
  g_byte_array_free (msg->buf, TRUE);
  g_free (msg);
}

static RTMPMessage *
client_get_rtmp_message (Client * client, guint8 chunk_stream_id)
{
  RTMPMessage *msg = g_hash_table_lookup (client->rtmp_messages,
      GINT_TO_POINTER (chunk_stream_id));
  if (msg == NULL) {
    msg = rtmp_message_new ();
    g_hash_table_insert (client->rtmp_messages,
        GINT_TO_POINTER (chunk_stream_id), msg);
  }
  return msg;
}

static PexRtmpServerStatus
client_incoming_handshake (Client * client)
{
  if (client->handshake_state == HANDSHAKE_START) {
    guint len = HANDSHAKE_LENGTH + 1;
    if (client->buf->len >= len) {
      /* receive the handshake from the client */
      if (!pex_rtmp_handshake_process (client->handshake, client->buf->data,
              len)) {
        GST_WARNING_OBJECT (client->server, "Unable to process handshake");
        return PEX_RTMP_SERVER_STATUS_HANDSHAKE_PROCESS_FAILED;
      }
      client->buf = g_byte_array_remove_range (client->buf, 0, len);

      /* send a reply */
      client->send_queue = g_byte_array_append (client->send_queue,
          pex_rtmp_handshake_get_buffer (client->handshake),
          pex_rtmp_handshake_get_length (client->handshake));
      PexRtmpServerStatus ret = client_send (client);
      if (ret != PEX_RTMP_SERVER_STATUS_OK) {
        GST_WARNING_OBJECT (client->server, "Unable to send handshake reply");
        return ret;
      }

      client->handshake_state = HANDSHAKE_STAGE1;
    }
  } else if (client->handshake_state == HANDSHAKE_STAGE1) {
    guint len = HANDSHAKE_LENGTH;
    if (client->buf->len >= len) {
      /* receive another handshake */
      if (!pex_rtmp_handshake_verify_reply (client->handshake,
              client->buf->data)) {
        GST_WARNING_OBJECT (client->server, "Could not verify handshake reply");
        return PEX_RTMP_SERVER_STATUS_HANDSHAKE_VERIFY_FAILED;
      }
      client->buf = g_byte_array_remove_range (client->buf, 0, len);

      client->handshake_state = HANDSHAKE_DONE;
    }
  }
  return PEX_RTMP_SERVER_STATUS_OK;
}

static PexRtmpServerStatus
client_outgoing_handshake (Client * client)
{
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;

  if (client->handshake_state == HANDSHAKE_START) {
    guint8 buf[HANDSHAKE_LENGTH + 1];
    /* first byte is Handshake Type */
    buf[0] = HANDSHAKE_PLAINTEXT;
    /* Next 4 is Uptime, and 4 more is FMS version */
    /* we set everything to 0 */
    memset (&buf[1], 0, 8);
    /* rest of the buffer is random numbers */
    for (gint i = 9; i < HANDSHAKE_LENGTH + 1; i++)
      buf[i] = 1;               /* 1 is random... */

    client->send_queue = g_byte_array_append (client->send_queue,
        buf, HANDSHAKE_LENGTH + 1);
    ret = client_send (client);
    if (ret != PEX_RTMP_SERVER_STATUS_OK) {
      GST_WARNING_OBJECT (client->server,
          "Unable to send outgoing handshake (1)");
      goto done;
    }

    client->handshake_state = HANDSHAKE_STAGE1;
  } else if (client->handshake_state == HANDSHAKE_STAGE1) {
    guint len = HANDSHAKE_LENGTH + 1;
    if (client->buf->len >= len) {
      /* check that the first byte says PLAINTEXT */
      if (client->buf->data[0] != HANDSHAKE_PLAINTEXT) {
        GST_WARNING_OBJECT (client->server, "Handshake is not plaintext");
        ret = PEX_RTMP_SERVER_STATUS_HANDSHAKE_PLAINTEXT_FAILED;
        goto done;
      }
      client->buf = g_byte_array_remove_range (client->buf, 0, 1);

      guint32 server_uptime;
      guint8 fms_version[4];
      memcpy (&server_uptime, &client->buf->data[0], 4);
      memcpy (&fms_version, &client->buf->data[4], 4);
      server_uptime = ntohl (server_uptime);
      GST_DEBUG_OBJECT (client->server,
          "Server Uptime: %u, FMS Version: %u.%u.%u.%u", server_uptime,
          fms_version[0], fms_version[1], fms_version[2], fms_version[3]);

      client->send_queue = g_byte_array_append (client->send_queue,
          &client->buf->data[0], HANDSHAKE_LENGTH);
      ret = client_send (client);
      if (ret != PEX_RTMP_SERVER_STATUS_OK) {
        GST_WARNING_OBJECT (client->server,
            "Unable to send outgoing handshake (2)");
        goto done;
      }
      client->buf =
          g_byte_array_remove_range (client->buf, 0, HANDSHAKE_LENGTH);
      client->handshake_state = HANDSHAKE_STAGE2;
    }
  }
  if (client->handshake_state == HANDSHAKE_STAGE2 &&
      client->buf->len >= HANDSHAKE_LENGTH) {
    client->buf = g_byte_array_remove_range (client->buf, 0, HANDSHAKE_LENGTH);
    ret = client_do_connect (client);
    if (ret != PEX_RTMP_SERVER_STATUS_OK)
      goto done;

    client->handshake_state = HANDSHAKE_DONE;
  }

done:
  return ret;
}


void
client_get_poll_ctl (Client * client, gboolean * read, gboolean * write)
{
  *read = FALSE;
  *write = FALSE;

  switch (client->state) {
    case CLIENT_TCP_HANDSHAKE_IN_PROGRESS:
      *write = TRUE;
      break;
    case CLIENT_TLS_HANDSHAKE_IN_PROGRESS:
      *read = TRUE;
      *write = TRUE;
      break;
    case CLIENT_TLS_HANDSHAKE_WANT_READ:
      *read = TRUE;
      break;
    case CLIENT_TLS_HANDSHAKE_WANT_WRITE:
      *write = TRUE;
      break;
    default:
      *read = TRUE;
      if (client->send_queue->len > 0 || client->ssl_read_blocked_on_write)
        *write = TRUE;
      break;
  }
}

static PexRtmpServerStatus
client_connected (Client * client)
{
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;
  client->state = CLIENT_CONNECTED;

  if (client->dialout_path) {
    ret = client_outgoing_handshake (client);
  }

  return ret;
}

#ifdef HAVE_OPENSSL

static PexRtmpServerStatus
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
    if (error == SSL_ERROR_WANT_READ) {
      client->state = CLIENT_TLS_HANDSHAKE_WANT_READ;
    } else if (error == SSL_ERROR_WANT_WRITE) {
      client->state = CLIENT_TLS_HANDSHAKE_WANT_WRITE;
    } else {
      GST_WARNING_OBJECT (client->server,
          "Unable to establish ssl-connection (error=%d, ret=%d, errno=%d)",
          error, ret, errno);
      ssl_print_errors ();
      return PEX_RTMP_SERVER_STATUS_SSL_ACCEPT_FAILED;
    }
  } else {
    return client_connected (client);
  }

  return PEX_RTMP_SERVER_STATUS_OK;
}

static PexRtmpServerStatus
client_begin_ssl (Client * client)
{
  client->ssl = SSL_new (client->ssl_ctx);
  SSL_set_app_data (client->ssl, client->remote_host);
  SSL_set_fd (client->ssl, client->fd);

  client->state = CLIENT_TLS_HANDSHAKE_IN_PROGRESS;

  return client_drive_ssl (client);
}

gboolean
client_add_incoming_ssl (Client * client,
    const gchar * cert_file, const gchar * key_file,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled)
{
  client->ssl_ctx = ssl_add_incoming (cert_file, key_file, ca_file, ca_dir,
      ciphers, tls1_enabled);
  return client->ssl_ctx != NULL;
}

gboolean
client_add_outgoing_ssl (Client * client,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled)
{
  client->ssl_ctx = ssl_add_outgoing (ca_file, ca_dir, ciphers, tls1_enabled);
  return client->ssl_ctx != NULL;
}

#endif /* HAVE_OPENSSL */

PexRtmpServerStatus
client_send (Client * client)
{
  if (client->state == CLIENT_TCP_HANDSHAKE_IN_PROGRESS) {
    int error;
    socklen_t error_len = sizeof (error);

    getsockopt (client->fd, SOL_SOCKET, SO_ERROR, (void *) &error, &error_len);

    if (error != 0) {
      GST_WARNING_OBJECT (client->server,
          "error in client TCP handshake (%s): %s", client->path,
          strerror (error));
      return PEX_RTMP_SERVER_STATUS_TCP_HANDSHAKE_FAILED;
    }

#ifdef HAVE_OPENSSL
    if (client->use_ssl) {
      return client_begin_ssl (client);
    }
#endif /* HAVE_OPENSSL */

    return client_connected (client);
  }

#ifdef HAVE_OPENSSL
  if (client->state == CLIENT_TLS_HANDSHAKE_IN_PROGRESS ||
      client->state == CLIENT_TLS_HANDSHAKE_WANT_READ ||
      client->state == CLIENT_TLS_HANDSHAKE_WANT_WRITE) {
    return client_drive_ssl (client);
  }
#endif /* HAVE_OPENSSL */

  ssize_t written;

   if (client->use_ssl) {
#ifdef HAVE_OPENSSL
    if (client->ssl_read_blocked_on_write) {
      return client_receive (client);
    } else if (client->send_queue->len == 0) {
      return PEX_RTMP_SERVER_STATUS_OK;
    }
    client->ssl_write_blocked_on_read = FALSE;
    written = SSL_write (client->ssl,
        client->send_queue->data, client->send_queue->len);
    if (written <= 0) {
      int error = SSL_get_error (client->ssl, written);
      if (error == SSL_ERROR_WANT_READ) {
        client->ssl_write_blocked_on_read = TRUE;
        return PEX_RTMP_SERVER_STATUS_OK;
      } else if (error == SSL_ERROR_WANT_WRITE) {
        return PEX_RTMP_SERVER_STATUS_OK;
      }

      GST_WARNING_OBJECT (client->server, "unable to write to a client (%s)",
          client->path);
      ssl_print_errors ();
      return PEX_RTMP_SERVER_STATUS_SSL_WRITE_FAILED;
    }
#else
    g_assert_not_reached ();
#endif /* HAVE_OPENSSL */
  } else {
#if defined(__APPLE__) || defined (G_OS_WIN32)
    written = send (client->fd,
        client->send_queue->data, client->send_queue->len, 0);
#else
    written = send (client->fd,
        client->send_queue->data, client->send_queue->len, MSG_NOSIGNAL);
#endif
    if (written < 0) {
      if (errno == EAGAIN || errno == EINTR)
        return PEX_RTMP_SERVER_STATUS_OK;
      GST_WARNING_OBJECT (client->server,
          "unable to write to a client (%s): %s", client->path,
          strerror (errno));
      return PEX_RTMP_SERVER_STATUS_SEND_FAILED;
    }
  }

  if (written > 0) {
    client->send_queue =
        g_byte_array_remove_range (client->send_queue, 0, written);
  }
  return PEX_RTMP_SERVER_STATUS_OK;
}

static PexRtmpServerStatus
client_handle_flv_buffer (Client * client, GstBuffer * buf)
{
  RTMPMessage msg;
  GstMapInfo map;
  guint payload_size;
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_BAD;
  guint total_parsed = 0;

  gst_buffer_map (buf, &map, GST_MAP_READ);

  GST_DEBUG_OBJECT (client->server, "Got flv buffer of size: %u",
      (guint)map.size);

  while (total_parsed < map.size) {
    guint8 *data = &map.data[total_parsed];
    guint parsed = 0;

    if ((parsed = flv_parse_header (data))) {
      total_parsed += parsed;
      GST_DEBUG_OBJECT (client->server, "Found FLV header!");
      continue;
    }

    /* ignore if we don't parse */
    if (!(parsed = flv_parse_tag (data, map.size - total_parsed,
        &msg.type, &payload_size, &msg.abs_timestamp))) {
      GST_WARNING_OBJECT (client->server, "Could not parse header!");
      goto done;
    }

    GST_DEBUG_OBJECT (client->server,
        "parsed %u: Got flv buffer with type: 0x%x, payload_size: %u",
        total_parsed, msg.type, payload_size);

    if (msg.type == MSG_AUDIO || msg.type == MSG_VIDEO) {
      client->buf = g_byte_array_append (client->buf,
          data + parsed, payload_size);
      msg.len = payload_size;
      msg.buf = client->buf;
      ret = client_handle_message (client, &msg);
      client->buf = g_byte_array_remove_range (client->buf, 0, client->buf->len);
    }

    total_parsed += (parsed + payload_size + 4);
  }

done:
  gst_buffer_unmap (buf, &map);
  return ret;
}

PexRtmpServerStatus
client_handle_flv (Client * client)
{
  PexRtmpServerStatus ret = PEX_RTMP_SERVER_STATUS_OK;
  GstBuffer *buf;
  while (ret == PEX_RTMP_SERVER_STATUS_OK &&
      (buf = gst_buffer_queue_try_pop (client->flv_queue))) {
    ret = client_handle_flv_buffer (client, buf);
    gst_buffer_unref (buf);
  }
  return ret;
}

gboolean
client_push_flv (Client * client, GstBuffer * buf)
{
  return gst_buffer_queue_push (client->flv_queue, buf);
}

gboolean
client_pull_flv (Client * client, GstBuffer ** buf)
{
  *buf = gst_buffer_queue_pop (client->flv_queue);
  return *buf != NULL;
}

void
client_unlock_flv_pull (Client * client)
{
  gst_buffer_queue_flush (client->flv_queue);
}

gboolean
client_has_flv_data (Client * client)
{
  return gst_buffer_queue_length (client->flv_queue) > 0;
}

PexRtmpServerStatus
client_receive (Client * client)
{
  guint8 chunk[4096];
  gint got;

#if HAVE_OPENSSL
  if (client->state == CLIENT_TLS_HANDSHAKE_IN_PROGRESS ||
      client->state == CLIENT_TLS_HANDSHAKE_WANT_READ ||
      client->state == CLIENT_TLS_HANDSHAKE_WANT_WRITE) {
    return client_drive_ssl (client);
  }
#endif /* HAVE_OPENSSL */

  if (client->use_ssl) {
#if HAVE_OPENSSL
    if (client->ssl_write_blocked_on_read) {
      return client_send (client);
    }
    client->ssl_read_blocked_on_write = FALSE;
    got = SSL_read (client->ssl, &chunk[0], sizeof (chunk));
    if (got <= 0) {
      int error = SSL_get_error (client->ssl, got);
      if (error == SSL_ERROR_WANT_READ) {
        return PEX_RTMP_SERVER_STATUS_OK;
      } else if (error == SSL_ERROR_WANT_WRITE) {
        client->ssl_read_blocked_on_write = TRUE;
        return PEX_RTMP_SERVER_STATUS_OK;
      }
      GST_WARNING_OBJECT (client->server, "unable to read from a client");
      ssl_print_errors ();
      return PEX_RTMP_SERVER_STATUS_SSL_READ_FAILED;
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
        return PEX_RTMP_SERVER_STATUS_SSL_READ_FAILED;
      }

      client->buf = g_byte_array_append (client->buf, chunk, got);
      GST_LOG_OBJECT (client->server, "Read %d bytes", got);
      GST_MEMDUMP_OBJECT (client->server, "Message contents", chunk, got);

      remaining -= got;
    }
#else
    g_assert_not_reached ();
#endif /* HAVE_OPENSSL */
  } else {
    got = recv (client->fd, &chunk[0], sizeof (chunk), 0);
    if (got == 0) {
      GST_DEBUG_OBJECT (client->server, "EOF from a client");
      return PEX_RTMP_SERVER_STATUS_RECV_EOF;
    } else if (got < 0) {
      if (errno == EAGAIN || errno == EINTR)
        return PEX_RTMP_SERVER_STATUS_OK;
      GST_DEBUG_OBJECT (client->server, "unable to read from a client: %s",
          strerror (errno));
      return PEX_RTMP_SERVER_STATUS_RECV_FAILED;
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
    guint8 fmt = flags >> 6;    /* 5.3.1.2 */
    guint8 chunk_stream_id = flags & 0x3f;
    guint header_len = CHUNK_MSG_HEADER_LENGTH[fmt];

    if (client->buf->len < header_len) {
      /* need more data */
      break;
    }

    RTMPHeader *header = (RTMPHeader *) & client->buf->data[0];
    RTMPMessage *msg = client_get_rtmp_message (client, chunk_stream_id);

    /* only get the message fmt from beginning of a new message */
    if (msg->buf->len == 0) {
      msg->fmt = fmt;
    }

    if (header_len >= 8) {
      msg->len = GST_READ_UINT24_BE (header->msg_len);
      if (msg->len < msg->buf->len) {
        GST_WARNING_OBJECT (client->server, "invalid msg length");
        return PEX_RTMP_SERVER_STATUS_INVALID_MSG_LEN;
      }
      msg->type = header->msg_type_id;
    }

    if (msg->len == 0) {
      GST_WARNING_OBJECT (client->server, "message with 0 length");
      return PEX_RTMP_SERVER_STATUS_INVALID_MSG_LEN;
    }

    if (header_len >= 12) {
      msg->msg_stream_id = header->msg_stream_id;
    }

    /* timestamp */
    if (header_len >= 4) {
      msg->timestamp = GST_READ_UINT24_BE (header->timestamp);
      /* extended timestamps are always absolute */
      if (msg->timestamp == EXT_TIMESTAMP_LIMIT) {
        /* check we have enough bytes to read the extended timestamp */
        if (client->buf->len < header_len + 4)
          break;

        GST_DEBUG_OBJECT (client->server, "Using extended timestamp");
        msg->abs_timestamp = GST_READ_UINT32_BE (&client->buf->data[header_len]);
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
    msg->buf =
        g_byte_array_append (msg->buf, &client->buf->data[header_len],
        chunk_size);
    client->buf =
        g_byte_array_remove_range (client->buf, 0, header_len + chunk_size);

    if (msg->buf->len == msg->len) {
      PexRtmpServerStatus ret = client_handle_message (client, msg);
      if (ret != PEX_RTMP_SERVER_STATUS_OK) {
        return ret;
      }
      msg->buf = g_byte_array_remove_range (msg->buf, 0, msg->buf->len);
    }
  }

  return PEX_RTMP_SERVER_STATUS_OK;
}

gboolean
client_tcp_connect (Client * client)
{
  gboolean ret = FALSE;
  gchar **address;

  gchar **addressv = g_strsplit (client->addresses, ",", 1024);
  if (!addressv[0]) {
    GST_WARNING ("No more addresses");
    goto done;
  }

  g_assert (client->fd == INVALID_FD);
  for (address = addressv; *address; address++) {
    GST_INFO_OBJECT (client->server, "Trying to connect to %s:%d, from port %d",
        *address, client->port, client->src_port);
    tcp_connect (&client->fd, *address, client->port, client->src_port,
        client->tcp_syncnt);
    if (client->fd != INVALID_FD) {
      GST_INFO_OBJECT (client->server,
          "Connected to %s:%d from port %d with fd %d", *address,
          client->port, client->src_port, client->fd);
      ret = TRUE;
      break;
    }
  }

done:
  g_strfreev (addressv);
  return ret;
}

gboolean
client_add_external_connect (Client * client,
    gboolean publisher,
    const gchar * path,
    const gchar * url,
    const gchar * addresses,
    gint src_port,
    gint tcp_syncnt)
{
  if (!parse_rtmp_url (url,
          &client->protocol, &client->port, &client->remote_host, &client->app,
          &client->dialout_path, &client->username, &client->password)) {
    return FALSE;
  }

  client->publisher = publisher;
  client->path = g_strdup (path);
  client->url = g_strdup (url);
  if (addresses) {
    client->addresses = g_strdup (addresses);
  } else {
    client->addresses = g_strdup (client->remote_host);
  }
  client->src_port = src_port;
  client->tcp_syncnt = tcp_syncnt;

  client->use_ssl = (g_strcmp0 (client->protocol, "rtmps") == 0);
#ifndef HAVE_OPENSSL
  if (client->use_ssl) {
    GST_ERROR_OBJECT (client->server, "Can't connect with rtmps without OPENSSL");
    return FALSE;
  }
#endif /* HAVE_OPENSSL */

  const gchar *tcUrlFmt = "%s://%s:%d/%s";
  if (strchr (client->remote_host, ':')) {     /* ipv6 */
    tcUrlFmt = "%s://[%s]:%d/%s";
  }
  client->tcUrl = g_strdup_printf (tcUrlFmt, client->protocol,
      client->remote_host, client->port, client->app);

  return TRUE;
}

void
client_configure_direct (Client * client, const gchar * path, gboolean publisher)
{
  client->direct = TRUE;
  client->publisher = publisher;
  client->path = g_strdup (path);
  client->flv_queue = gst_buffer_queue_new ();

  if (publisher) {
    client->recv_chunk_size = G_MAXUINT;
  } else {
    client->write_flv_header = TRUE;
    client->send_chunk_size = G_MAXUINT;
  }
}

Client *
client_new (GObject * server,
    Connections * connections,
    gint msg_stream_id,
    guint chunk_size,
    NotifyConnectionFunc notify_connection)
{
  Client *client = g_new0 (Client, 1);

  client->ref_count = 1;
  client->server = server;
  client->connections = connections;
  client->msg_stream_id = msg_stream_id;
  client->chunk_size = chunk_size;
  client->notify_connection = notify_connection;

  GST_DEBUG_OBJECT (client->server, "Chunk Size: %d, MSG Stream ID:%d\n",
      chunk_size, msg_stream_id);

  client->fd = INVALID_FD;
  client->state = CLIENT_TCP_HANDSHAKE_IN_PROGRESS;
  client->recv_chunk_size = DEFAULT_CHUNK_SIZE;
  client->send_chunk_size = DEFAULT_CHUNK_SIZE;
  client->window_size = DEFAULT_WINDOW_SIZE;

  client->rtmp_messages = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) rtmp_message_free);

  client->send_queue = g_byte_array_new ();
  client->buf = g_byte_array_new ();

  client->handshake = pex_rtmp_handshake_new ();
  client->handshake_state = HANDSHAKE_START;

  return client;
}

static void
client_free (Client * client)
{
  g_free (client->path);
  g_free (client->url);
  g_free (client->addresses);
  g_free (client->protocol);
  g_free (client->remote_host);
  g_free (client->app);
  g_free (client->dialout_path);
  g_free (client->username);
  g_free (client->password);
  g_free (client->tcUrl);
  g_free (client->opaque);
  g_free (client->salt);
  g_free (client->auth_token);

  g_hash_table_destroy (client->rtmp_messages);

  g_byte_array_free (client->buf, TRUE);
  g_byte_array_free (client->send_queue, TRUE);

  if (client->flv_queue)
    gst_buffer_queue_free (client->flv_queue);

  if (client->metadata)
    gst_structure_free (client->metadata);
  if (client->video_codec_data)
    g_byte_array_free (client->video_codec_data, TRUE);

  pex_rtmp_handshake_free (client->handshake);

  if (client->last_queue_overflow != NULL) {
    g_timer_destroy (client->last_queue_overflow);
  }

#ifdef HAVE_OPENSSL
  /* ssl */
  if (client->ssl_ctx)
    SSL_CTX_free (client->ssl_ctx);
  if (client->ssl)
    SSL_free (client->ssl);
#endif /* HAVE_OPENSSL */

  g_free (client);
}

void
client_ref (Client * client)
{
  g_atomic_int_add (&client->ref_count, 1);
}

void
client_unref (Client * client)
{
  gint old_ref = g_atomic_int_add (&client->ref_count, -1);
  if (old_ref == 1) {
    client_free (client);
  }
}
