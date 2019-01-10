/*
 * Pexip
 * Copyright (C) 2018 Pexip <pexip.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gst/gst.h>

#include "pexrtmpserversink.h"
#include "rtmpserver.h"

GST_DEBUG_CATEGORY_STATIC (pex_rtmp_server_sink_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_sink_debug

enum
{
  PROP_0,
  PROP_SERVER,
  PROP_PATH,
  PROP_DIALOUT_URL,
  PROP_BYTES_SENT,
  PROP_PACKETS_SENT,
};

static GstStaticPadTemplate sink_template = GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-flv")
    );

struct _PexRTMPServerSink
{
  GstBaseSink parent;

  PexRtmpServer *server;
  gboolean spawned_server;

  gboolean on_play;
  gboolean on_play_done;

  GstBuffer *header;
  gboolean first;

  /* properties */
  gchar *path;
  gchar *dialout_url;
  guint bytes_sent;
  guint packets_sent;
};

#define pex_rtmp_server_sink_parent_class parent_class
G_DEFINE_TYPE (PexRTMPServerSink, pex_rtmp_server_sink, GST_TYPE_BASE_SINK);


static gboolean
_on_play (PexRTMPServerSink * sink, const gchar * path)
{
  GST_INFO_OBJECT (sink, "on-play called for path %s", path);
  if (g_strcmp0 (path, sink->path) == 0)
    sink->on_play = TRUE;
  return FALSE;
}

static void
_on_play_done (PexRTMPServerSink * sink, const gchar * path)
{
  GST_INFO_OBJECT (sink, "on-play-done called for path %s", path);
  if (g_strcmp0 (path, sink->path) == 0)
    sink->on_play_done = TRUE;
}

static gboolean
pex_rtmp_server_sink_start (GstBaseSink * basesink)
{
  PexRTMPServerSink *sink = PEX_RTMP_SERVER_SINK_CAST (basesink);

  if (sink->path == NULL && sink->dialout_url == NULL) {
    GST_ERROR_OBJECT (sink, "you need to set a path or uri");
    return FALSE;
  }

  if (sink->path && sink->server == NULL) {
    GST_ERROR_OBJECT (sink, "If using path you need to give me a server!");
    return FALSE;
  }

  if (sink->server == NULL && sink->dialout_url) {
    GST_INFO_OBJECT (sink, "Creating RTMP server");
    sink->server = pex_rtmp_server_new ("pexapp",
        0, 0, NULL, NULL, NULL, NULL, NULL, TRUE, FALSE);

    g_signal_connect_swapped (sink->server, "on-play",
        (GCallback) _on_play, sink);
    g_signal_connect_swapped (sink->server, "on-play-done",
        (GCallback) _on_play_done, sink);

    pex_rtmp_server_start (sink->server);
    sink->spawned_server = TRUE;

    /* create a path to use between sink and server */
    sink->path = g_strdup ("pexpath");

    gboolean ret = pex_rtmp_server_dialout (sink->server,
        sink->path, sink->dialout_url, NULL, 23000);
    if (!ret) {
      GST_ERROR_OBJECT (sink, "Could not dial out to %s", sink->dialout_url);
      return FALSE;
    }

    /* FIXME: not very nice, think about how this could time out */
    while (!sink->on_play && !sink->on_play_done)
      g_usleep (G_USEC_PER_SEC / 100);

    if (!sink->on_play || sink->on_play_done)
      return FALSE;
  }

  pex_rtmp_server_add_direct_publisher (sink->server, sink->path);

  sink->first = TRUE;

  return TRUE;
}

static gboolean
pex_rtmp_server_sink_stop (GstBaseSink * basesink)
{
  PexRTMPServerSink *sink = PEX_RTMP_SERVER_SINK_CAST (basesink);

  if (sink->header) {
    gst_buffer_unref (sink->header);
    sink->header = NULL;
  }

  if (sink->spawned_server) {
    pex_rtmp_server_stop (sink->server);
  }

  return TRUE;
}

static GstFlowReturn
pex_rtmp_server_sink_render (GstBaseSink * basesink, GstBuffer * buf)
{
  PexRTMPServerSink *sink = PEX_RTMP_SERVER_SINK_CAST (basesink);
  gboolean need_unref = FALSE;

  if (sink->on_play_done) {
    GST_WARNING_OBJECT (sink, "Dial-Out disconnected, stopping");
    gst_buffer_unref (buf);
    return GST_FLOW_EOS;
  }

  /* Ignore buffers that are in the stream headers (caps) */
  if (GST_BUFFER_FLAG_IS_SET (buf, GST_BUFFER_FLAG_HEADER)) {
    return GST_FLOW_OK;
  }

  if (sink->first && sink->header) {
    buf = gst_buffer_append (gst_buffer_ref (sink->header),
        gst_buffer_ref (buf));
    need_unref = TRUE;
    sink->first = FALSE;
  }

  gboolean ret = pex_rtmp_server_publish_flv (sink->server, sink->path, buf);
  if (ret) {
    sink->bytes_sent = gst_buffer_get_size (buf);
    sink->packets_sent++;
    GST_DEBUG_OBJECT (sink, "publishing %" GST_PTR_FORMAT, buf);
    //gst_util_dump_buffer (buf);
  } else {
    GST_WARNING_OBJECT (sink, "Publish FLV returned FALSE");
  }

  if (need_unref)
    gst_buffer_unref (buf);

  return GST_FLOW_OK;
}

static gboolean
pex_rtmp_server_sink_setcaps (GstBaseSink * basesink, GstCaps * caps)
{
  PexRTMPServerSink *sink = PEX_RTMP_SERVER_SINK_CAST (basesink);
  GstStructure *s;
  const GValue *sh;
  GArray *buffers;
  gint i;

  GST_DEBUG_OBJECT (sink, "caps set to %" GST_PTR_FORMAT, caps);

  s = gst_caps_get_structure (caps, 0);
  sh = gst_structure_get_value (s, "streamheader");
  if (sh == NULL) {
    GST_DEBUG_OBJECT (sink, "No streamheader in caps");
    return TRUE;
  }

  /* Clear our current header buffer */
  if (sink->header) {
    gst_buffer_unref (sink->header);
    sink->header = NULL;
  }

  sink->header = gst_buffer_new ();
  buffers = g_value_peek_pointer (sh);

  /* Concatenate all buffers in streamheader into one */
  for (i = 0; i < buffers->len; ++i) {
    GValue *val;
    GstBuffer *buf;

    val = &g_array_index (buffers, GValue, i);
    buf = g_value_peek_pointer (val);

    gst_buffer_ref (buf);

    sink->header = gst_buffer_append (sink->header, buf);
  }

  GST_DEBUG_OBJECT (sink, "have %" G_GSIZE_FORMAT " bytes of header data",
      gst_buffer_get_size (sink->header));

  return TRUE;
}

static void
pex_rtmp_server_sink_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  PexRTMPServerSink *sink = PEX_RTMP_SERVER_SINK_CAST (object);

  switch (prop_id) {
    case PROP_SERVER:
      g_value_set_object (value, sink->server);
      break;
    case PROP_PATH:
      g_value_set_string (value, sink->path);
      break;
    case PROP_DIALOUT_URL:
      g_value_set_string (value, sink->dialout_url);
      break;
    case PROP_BYTES_SENT:
      g_value_set_uint (value, sink->bytes_sent);
      break;
    case PROP_PACKETS_SENT:
      g_value_set_uint (value, sink->packets_sent);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
pex_rtmp_server_sink_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  PexRTMPServerSink *sink = PEX_RTMP_SERVER_SINK_CAST (object);

  switch (prop_id) {
    case PROP_SERVER:
      sink->server = g_object_ref (g_value_get_object (value));
      break;
    case PROP_PATH:
      g_free (sink->path);
      sink->path = g_strdup (g_value_get_string (value));
      break;
    case PROP_DIALOUT_URL:
      g_free (sink->dialout_url);
      sink->dialout_url = g_strdup (g_value_get_string (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
pex_rtmp_server_sink_finalize (GObject * object)
{
  PexRTMPServerSink *sink = PEX_RTMP_SERVER_SINK_CAST (object);

  if (sink->server)
    g_object_unref (G_OBJECT (sink->server));
  g_free (sink->path);
  g_free (sink->dialout_url);

  G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
pex_rtmp_server_sink_class_init (PexRTMPServerSinkClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;
  GstBaseSinkClass *gstbasesink_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;
  gstbasesink_class = (GstBaseSinkClass *) klass;

  gobject_class->finalize = pex_rtmp_server_sink_finalize;
  gobject_class->set_property = pex_rtmp_server_sink_set_property;
  gobject_class->get_property = pex_rtmp_server_sink_get_property;

  g_object_class_install_property (gobject_class, PROP_SERVER,
      g_param_spec_object ("server", "RTMP Server",
          "The Pex RTMP server to use", PEX_TYPE_RTMP_SERVER,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_PATH,
      g_param_spec_string ("path", "RTMP Path",
          "The path to use towards the server",
          NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_DIALOUT_URL,
      g_param_spec_string ("dialout-url", "RTMP Dialout URL",
          "The RTMP URL to dial out to",
          NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_BYTES_SENT,
      g_param_spec_uint ("bytes-sent", "Bytes Sent",
          "Number of bytes sent", 0, G_MAXUINT, 0,
          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_PACKETS_SENT,
      g_param_spec_uint ("packets-sent", "Packets Sent",
          "Number of packets sent", 0, G_MAXUINT, 0,
          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  gst_element_class_set_static_metadata (gstelement_class,
      "RTMP output sink",
      "Sink/Network", "Sends FLV content to the Pex RTMP server",
      "Havard Graff <havard@pexip.com>");

  gst_element_class_add_static_pad_template (gstelement_class, &sink_template);

  gstbasesink_class->start = GST_DEBUG_FUNCPTR (pex_rtmp_server_sink_start);
  gstbasesink_class->stop = GST_DEBUG_FUNCPTR (pex_rtmp_server_sink_stop);
  gstbasesink_class->render = GST_DEBUG_FUNCPTR (pex_rtmp_server_sink_render);
  gstbasesink_class->set_caps =
      GST_DEBUG_FUNCPTR (pex_rtmp_server_sink_setcaps);

  GST_DEBUG_CATEGORY_INIT (pex_rtmp_server_sink_debug, "rtmpserversink", 0,
      "RTMP server element");
}

static void
pex_rtmp_server_sink_init (PexRTMPServerSink * sink)
{
  (void) sink;
}
