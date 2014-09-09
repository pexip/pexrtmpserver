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

#ifdef __APPLE__
  ssize_t written = send (client->fd,
      client->send_queue->data, client->send_queue->len, 0);
#else
  ssize_t written = send (client->fd,
      client->send_queue->data, client->send_queue->len, MSG_NOSIGNAL);
#endif

  if (written < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    printf ("unable to write to a client: %s\n", strerror (errno));
    return FALSE;
  }

  client->send_queue = g_byte_array_remove_range (client->send_queue, 0, written);
  return TRUE;
}

static void
client_rtmp_send (Client * client, guint8 type, guint32 endpoint,
    GByteArray * buf, unsigned long timestamp, int channel_num)
{
  if (endpoint == STREAM_ID) {
    /*
     * For some unknown reason, stream-related msgs must be sent
     * on a specific channel.
     */
    channel_num = CHAN_STREAM;
  }

  RTMP_Header header;
  header.flags = (channel_num & 0x3f) | (0 << 6);
  header.msg_type = type;
  set_be24 (header.timestamp, timestamp);
  set_be24 (header.msg_len, buf->len);
  set_le32 (header.endpoint, endpoint);

  client->send_queue = g_byte_array_append (client->send_queue,
      (guint8 *) & header, sizeof (header));

  client->written_seq += sizeof header;

  size_t pos = 0;
  while (pos < buf->len) {
    if (pos) {
      guint8 flags = (channel_num & 0x3f) | (3 << 6);
      client->send_queue = g_byte_array_append (client->send_queue, &flags, 1);

      client->written_seq += 1;
    }

    size_t chunk = buf->len - pos;
    if (chunk > client->chunk_len)
      chunk = client->chunk_len;
    client->send_queue = g_byte_array_append (client->send_queue,
        &buf->data[pos], chunk);

    client->written_seq += chunk;
    pos += chunk;
  }

  client_try_to_send (client);
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

  client_rtmp_send (client, MSG_INVOKE, CONTROL_ID, invoke->buf, 0, CHAN_RESULT);
  amf_enc_free (invoke);
}

static void
client_handle_connect (Client * client, double txid, AmfDec * dec)
{
  GstStructure * params = amf_dec_load_object (dec);

  /* FIXME: support multiple applications */
  //if (strcmp (app, application_name) != 0) {
  //  g_warning ("Unsupported application: %s", app);
  //}

  gchar * params_str = gst_structure_to_string (params);
  printf ("connect: %s\n", params_str);
  g_free (params_str);
  gst_structure_free (params);

  GValue version = G_VALUE_INIT;
  g_value_init (&version, GST_TYPE_STRUCTURE);
  GstStructure * version_s = gst_structure_new ("object",
      "capabilities", G_TYPE_DOUBLE, 255.0,
      "fmsVer", G_TYPE_STRING, "FMS/4,5,1,484",
      "mode", G_TYPE_DOUBLE, 1.0,
      NULL);
  gst_value_set_structure (&version, version_s);
  gst_structure_free (version_s);

  GValue status = G_VALUE_INIT;
  g_value_init (&status, GST_TYPE_STRUCTURE);
  GstStructure * status_s = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetConnection.Connect.Success",
      "description", G_TYPE_STRING, "Connection succeeded.",
      "level", G_TYPE_STRING, "status",
      "objectEncoding", G_TYPE_DOUBLE, 0.0,
      NULL);
  gst_value_set_structure (&status, status_s);
  gst_structure_free (status_s);

  client_send_reply (client, txid, &version, &status);
  g_value_unset (&version);
  g_value_unset (&status);

/*
	guint32 chunk_len = htonl(1024);
	std::string set_chunk((char *) &chunk_len, 4);
	client_rtmp_send(client, MSG_SET_CHUNK, CONTROL_ID, set_chunk, 0,
		  MEDIA_CHANNEL);

	client->chunk_len = 1024;
*/
}

static void
client_handle_fcpublish (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec));           /* NULL */

  gchar * path = amf_dec_load_string (dec);
  debug ("fcpublish %s\n", path);


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

  client_rtmp_send (client, MSG_INVOKE, CONTROL_ID, invoke->buf, 0, CHAN_CONTROL);
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
  g_value_set_double (&stream_id, STREAM_ID);
  client_send_reply (client, txid, &null_value, &stream_id);
}

static gboolean
client_handle_publish (Client * client, double txid, AmfDec * dec)
{
  g_free (amf_dec_load (dec)); /* NULL */
  gchar * path = amf_dec_load_string (dec);
  debug ("publish %s\n", path);

  client->publisher = TRUE;
  g_free (client->path);
  client->path = path;

  gboolean reject_publish = FALSE;
  g_signal_emit_by_name(client->server, "on-publish", path, &reject_publish);
  if (reject_publish) {
    debug ("Not publishing due to signal rejecting publish\n");
    return FALSE;
  }
  connections_add_publisher (client->connections, client, path);
  printf ("publisher connected.\n");

  GstStructure * status = gst_structure_new ("object",
      "code", G_TYPE_STRING, "NetStream.Publish.Start",
      "description", G_TYPE_STRING, "Stream is now published.",
      "details", G_TYPE_STRING, path,
      "level", G_TYPE_STRING, "status",
      NULL);
  AmfEnc * invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "onStatus");
  amf_enc_write_double (invoke, 0.0);
  amf_enc_write_null (invoke);
  amf_enc_write_object (invoke, status);

  client_rtmp_send (client, MSG_INVOKE, STREAM_ID, invoke->buf, 0, CHAN_CONTROL);
  amf_enc_free (invoke);
  gst_structure_free (status);

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);

  /* Send Window Acknowledgement Size (5.4.4) */
  AmfEnc * enc = amf_enc_new ();
  amf_enc_add_int (enc, htonl (client->window_size));
  client_rtmp_send (client, MSG_WINDOW_ACK_SIZE, CONTROL_ID, enc->buf, 0, CHAN_CONTROL);
  amf_enc_free (enc);

  return TRUE;
}

static void
client_start_playback (Client * client)
{
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

  client_rtmp_send (client, MSG_INVOKE, STREAM_ID, invoke->buf, 0, CHAN_CONTROL);
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

  client_rtmp_send (client, MSG_INVOKE, STREAM_ID, invoke->buf, 0, CHAN_CONTROL);
  amf_enc_free (invoke);
  gst_structure_free (status);

  invoke = amf_enc_new ();
  amf_enc_write_string (invoke, "|RtmpSampleAccess");
  amf_enc_write_bool (invoke, TRUE);
  amf_enc_write_bool (invoke, TRUE);

  client_rtmp_send (client, MSG_NOTIFY, STREAM_ID, invoke->buf, 0, CHAN_CONTROL);
  amf_enc_free (invoke);

  client->playing = TRUE;
  client->ready = FALSE;

  connections_add_subscriber (client->connections, client, client->path);

  /* send any available metadata from the relevant publisher */
  Client * publisher = connections_get_publisher (client->connections, client->path);
  if (publisher && publisher->metadata) {
    debug("(%s) METADATA %p\n", client->path, publisher->metadata);
    AmfEnc * invoke = amf_enc_new ();
    amf_enc_write_string (invoke, "onMetaData");
    amf_enc_write_ecma (invoke, publisher->metadata);

    client_rtmp_send (client, MSG_NOTIFY, STREAM_ID, invoke->buf, 0, CHAN_CONTROL);
    amf_enc_free (invoke);
  }
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
    debug ("%p Not playing due to signal returning 0\n", client);
    return FALSE;
  }
  debug ("play %s\n", path);

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
  debug ("play2 %s\n", path);
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
    debug ("pausing\n");

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

    client_rtmp_send (client, MSG_INVOKE, STREAM_ID, invoke->buf, 0, CHAN_CONTROL);
    client->playing = FALSE;
  } else {
    client_start_playback (client);
  }

  GValue null_value = G_VALUE_INIT;
  client_send_reply (client, txid, &null_value, &null_value);
}

static void
client_handle_setdataframe (Client * client, AmfDec * dec, int msg_type)
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
  if (msg_type == MSG_DATA) {
    client->metadata = amf_dec_load_object(dec);
  } else {
    client->metadata = amf_dec_load_ecma (dec);
  }

  AmfEnc * notify = amf_enc_new ();
  amf_enc_write_string (notify, "onMetaData");
  amf_enc_write_ecma (notify, client->metadata);

  /* update all relevant subscribers with this metadata */
  GSList * subscribers = connections_get_subscribers (client->connections, client->path);
  for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
    Client * subscriber = (Client *)walk->data;
    client_rtmp_send (subscriber, MSG_NOTIFY, STREAM_ID, notify->buf, 0, CHAN_CONTROL);
  }

  amf_enc_free (notify);
}

static gboolean
client_handle_invoke (Client * client, const RTMP_Message * msg, AmfDec * dec)
{
  gboolean ret = TRUE;
  gchar * method = amf_dec_load_string (dec);
  double txid = amf_dec_load_number (dec);

  debug ("%p: invoked %s with txid %lf \n", client, method, txid);

  if (msg->endpoint == CONTROL_ID) {
    if (strcmp (method, "connect") == 0) {
      client_handle_connect (client, txid, dec);
    } else if (strcmp (method, "FCPublish") == 0) {
      client_handle_fcpublish (client, txid, dec);
    } else if (strcmp (method, "createStream") == 0) {
      client_handle_createstream (client, txid);
    }

  } else if (msg->endpoint == STREAM_ID) {
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

static gboolean
client_window_size_reached (Client *client)
{
  return (client->bytes_received_since_ack >= client->window_size);
}

static void
client_send_ack (Client *client)
{
  AmfEnc * enc= amf_enc_new ();
  amf_enc_add_int (enc, htonl(client->total_bytes_received));
  client->bytes_received_since_ack = 0;
  client_rtmp_send(client, MSG_ACK, CONTROL_ID, enc->buf, 0, CHAN_CONTROL);
  amf_enc_free(enc);
}

static gboolean
client_handle_message (Client * client, RTMP_Message * msg)
{
  /*
     debug("RTMP message %02x, len %zu, timestamp %ld\n", msg->type, msg->len,
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
        printf ("Not enough data\n");
        return FALSE;
      }
      client->read_seq = load_be32 (&msg->buf[pos]);
      break;

    case MSG_SET_CHUNK:
      if (pos + 4 > msg->buf->len) {
        printf ("Not enough data\n");
        return FALSE;
      }
      client->chunk_len = load_be32 (&msg->buf[pos]);
      debug ("chunk size set to %zu\n", client->chunk_len);
      break;

    case MSG_WINDOW_ACK_SIZE:
    {
      client->window_size = load_be32 (&msg->buf[pos]);
      debug ("%s window size set to %u\n", client->path, client->window_size);
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
      debug ("notify %s\n", type);
      if (msg->endpoint == STREAM_ID) {
        if (strcmp (type, "@setDataFrame") == 0) {
          client_handle_setdataframe (client, dec, MSG_NOTIFY);
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
      debug ("data %s\n", type);
      if (msg->endpoint == STREAM_ID) {
        if (strcmp (type, "@setDataFrame") == 0) {
          client_handle_setdataframe (client, dec, MSG_DATA);
        }
      }
      g_free (type);
      amf_dec_free (dec);
      break;
    }

    case MSG_AUDIO:
      if (!client->publisher) {
        printf ("not a publisher");
        return FALSE;
      }
      GSList * subscribers = connections_get_subscribers (client->connections, client->path);
      for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
        Client * subscriber = (Client *)walk->data;
        client_rtmp_send (subscriber, MSG_AUDIO, STREAM_ID, msg->buf, msg->timestamp, CHAN_CONTROL);
      }
      break;


    case MSG_VIDEO:
    {
      if (!client->publisher) {
        printf ("not a publisher");
        return FALSE;
      }
      guint8 flags = msg->buf->data[0];
      GSList * subscribers = connections_get_subscribers (client->connections, client->path);
      for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
        Client * subscriber = (Client *)walk->data;

        if (flags >> 4 == FLV_KEY_FRAME && !subscriber->ready) {
          AmfEnc * control = amf_enc_new ();
          amf_enc_add_short (control, htons (CONTROL_CLEAR_STREAM));
          amf_enc_add_int (control, htonl (STREAM_ID));

          client_rtmp_send (subscriber, MSG_USER_CONTROL, CONTROL_ID, control->buf, 0, CHAN_CONTROL);
          amf_enc_free (control);
          subscriber->ready = TRUE;
        }
        if (subscriber->ready) {
          client_rtmp_send (subscriber, MSG_VIDEO, STREAM_ID, msg->buf, msg->timestamp, CHAN_CONTROL);
        }
        else {
          printf ("VIDEO COMING IN FOR %s, but client not ready\n", client->path);
        }
      }
      break;
    }

    case MSG_FLASH_VIDEO:
      g_warning ("streaming FLV not supported");
      ret = FALSE;
      break;

    default:
      debug ("unhandled message: %02x\n", msg->type);
      hexdump (msg->buf->data, msg->buf->len);
      break;
  }

  return ret;
}

gboolean
client_receive (Client * client)
{
  guint8 chunk[4096];
  ssize_t got = recv (client->fd, &chunk[0], sizeof (chunk), 0);

  if (got == 0) {
    printf ("EOF from a client\n");
    return FALSE;
  } else if (got < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    printf ("unable to read from a client: %s\n", strerror (errno));
    return FALSE;
  }
  client->buf = g_byte_array_append (client->buf, chunk, got);

  while (client->buf->len != 0) {
    guint8 flags = client->buf->data[0];

    static const size_t
    HEADER_LENGTH[] = { 12, 8, 4, 1 };
    size_t header_len = HEADER_LENGTH[flags >> 6];

    if (client->buf->len < header_len) {
      /* need more data */
      break;
    }

    RTMP_Header header;
    memcpy (&header, &client->buf->data[0], header_len);

    RTMP_Message * msg = &client->messages[flags & 0x3f];

    if (header_len >= 8) {
      msg->len = load_be24 (header.msg_len);
      if (msg->len < msg->buf->len) {
        g_warning ("invalid msg length");
        return FALSE;
      }
      msg->type = header.msg_type;
    }
    if (header_len >= 12) {
      msg->endpoint = load_le32 (header.endpoint);
    }

    if (msg->len == 0) {
      g_warning ("message without a header");
      return FALSE;
    }
    size_t chunk = msg->len - msg->buf->len;
    if (chunk > client->chunk_len)
      chunk = client->chunk_len;

    if (client->buf->len < header_len + chunk) {
      /* need more data */
      break;
    }

    if (header_len >= 4) {
      unsigned long ts = load_be24 (header.timestamp);
      if (ts == 0xffffff) {
        g_warning ("ext timestamp not supported");
        return TRUE;
      }
      if (header_len < 12) {
        ts += msg->timestamp;
      }
      msg->timestamp = ts;
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


Client *
client_new (gint fd, Connections * connections, GObject * server)
{
  Client * client = g_new0 (Client, 1);

  client->connections = connections;
  client->server = server;

  client->fd = fd;
  client->chunk_len = DEFAULT_CHUNK_LEN;
  client->window_size = DEFAULT_WINDOW_SIZE;

  for (int i = 0; i < 64; ++i) {
    client->messages[i].timestamp = 0;
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
  g_free (client);
}
