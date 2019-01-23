/* PexRTMPServer
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gst/gst.h>
#include <gst/base/gstbasesrc.h>

#include "pexrtmpserversrc.h"
#include "pexrtmpserver.h"

GST_DEBUG_CATEGORY_STATIC (pex_rtmp_server_src_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_src_debug

enum
{
  PROP_0,
  PROP_SERVER,
  PROP_PATH,
  PROP_DIALIN_URL,
  PROP_BYTES_RECEIVED,
  PROP_PACKETS_RECEIVED,
};

static GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("video/x-flv")
    );

struct _PexRTMPServerSrc
{
  GstBaseSrc parent;

  PexRtmpServer *server;
  gboolean spawned_server;

  gboolean on_publish;
  gboolean on_publish_done;

  /* properties */
  gchar *path;
  gchar *dialin_url;
  guint bytes_received;
  guint packets_received;
};

#define pex_rtmp_server_src_parent_class parent_class
G_DEFINE_TYPE (PexRTMPServerSrc, pex_rtmp_server_src, GST_TYPE_PUSH_SRC);

static gboolean
_on_publish (PexRTMPServerSrc * src, const gchar * path)
{
  GST_INFO_OBJECT (src, "on-publish called for path %s", path);
  if (g_strcmp0 (path, src->path) == 0)
    src->on_publish = TRUE;
  return FALSE;
}

static void
_on_publish_done (PexRTMPServerSrc * src, const gchar * path)
{
  GST_INFO_OBJECT (src, "on-publish-done called for path %s", path);
  if (g_strcmp0 (path, src->path) == 0)
    src->on_publish_done = TRUE;
}

static gboolean
pex_rtmp_server_src_start (GstBaseSrc * basesrc)
{
  PexRTMPServerSrc *src = PEX_RTMP_SERVER_SRC_CAST (basesrc);

  if (src->path == NULL && src->dialin_url == NULL) {
    GST_ERROR_OBJECT (src, "you need to set a path or uri");
    return FALSE;
  }

  if (src->path && src->server == NULL) {
    GST_ERROR_OBJECT (src, "If using path you need to give me a server!");
    return FALSE;
  }

  if (src->server == NULL && src->dialin_url) {
    GST_INFO_OBJECT (src, "Creating RTMP server");
    src->server = pex_rtmp_server_new ("pexapp",
        0, 0, NULL, NULL, NULL, NULL, NULL, TRUE, FALSE);

    g_signal_connect_swapped (src->server, "on-publish",
        (GCallback) _on_publish, src);
    g_signal_connect_swapped (src->server, "on-publish-done",
        (GCallback) _on_publish_done, src);

    pex_rtmp_server_start (src->server);
    src->spawned_server = TRUE;

    /* create a path to use between src and server */
    src->path = g_strdup ("pexpath");

    gboolean ret = pex_rtmp_server_dialin (src->server,
        src->path, src->dialin_url, NULL, 22000);
    if (!ret) {
      GST_ERROR_OBJECT (src, "Could not dial out to %s", src->dialin_url);
      return FALSE;
    }

    /* FIXME: not very nice, think about how this could time out */
    while (!src->on_publish && !src->on_publish_done)
      g_usleep (G_USEC_PER_SEC / 100);

    if (!src->on_publish || src->on_publish_done)
      return FALSE;
  }

  pex_rtmp_server_add_direct_subscriber (src->server, src->path);

  return TRUE;
}

static gboolean
pex_rtmp_server_src_stop (GstBaseSrc * basesrc)
{
  PexRTMPServerSrc *src = PEX_RTMP_SERVER_SRC_CAST (basesrc);
  GST_DEBUG_OBJECT (src, "Stopping");

  pex_rtmp_server_remove_direct_subscriber (src->server, src->path);

  if (src->spawned_server) {
    pex_rtmp_server_stop (src->server);
  }

  return TRUE;
}

static gboolean
pex_rtmp_server_src_unlock (GstBaseSrc * basesrc)
{
  PexRTMPServerSrc *src = PEX_RTMP_SERVER_SRC_CAST (basesrc);
  pex_rtmp_server_flush_subscribe (src->server, src->path);
  return TRUE;
}

static GstFlowReturn
pex_rtmp_server_src_create (GstPushSrc * pushsrc, GstBuffer ** buf)
{
  PexRTMPServerSrc *src = PEX_RTMP_SERVER_SRC_CAST (pushsrc);
  GstFlowReturn flowret;

  if (src->on_publish_done) {
    GST_WARNING_OBJECT (src, "Dial-In disconnected, stopping");
    return GST_FLOW_EOS;
  }

  gboolean ret = pex_rtmp_server_subscribe_flv (src->server, src->path, buf);
  flowret = ret ? GST_FLOW_OK : GST_FLOW_EOS;

  if (ret) {
    src->bytes_received += gst_buffer_get_size (*buf);
    src->packets_received++;
    GST_LOG_OBJECT (src, "subscribing %" GST_PTR_FORMAT, *buf);
  }

  return flowret;
}

static void
pex_rtmp_server_src_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  PexRTMPServerSrc *src = PEX_RTMP_SERVER_SRC_CAST (object);

  switch (prop_id) {
    case PROP_SERVER:
      g_value_set_object (value, src->server);
      break;
    case PROP_PATH:
      g_value_set_string (value, src->path);
      break;
    case PROP_DIALIN_URL:
      g_value_set_string (value, src->dialin_url);
      break;
    case PROP_BYTES_RECEIVED:
      g_value_set_uint (value, src->bytes_received);
      break;
    case PROP_PACKETS_RECEIVED:
      g_value_set_uint (value, src->packets_received);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
pex_rtmp_server_src_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  PexRTMPServerSrc *src = PEX_RTMP_SERVER_SRC_CAST (object);

  switch (prop_id) {
    case PROP_SERVER:
      src->server = g_object_ref (g_value_get_object (value));
      break;
    case PROP_PATH:
      g_free (src->path);
      src->path = g_strdup (g_value_get_string (value));
      break;
    case PROP_DIALIN_URL:
      g_free (src->dialin_url);
      src->dialin_url = g_strdup (g_value_get_string (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
pex_rtmp_server_src_finalize (GObject * object)
{
  PexRTMPServerSrc *src = PEX_RTMP_SERVER_SRC_CAST (object);

  if (src->server)
    g_object_unref (G_OBJECT (src->server));
  g_free (src->path);
  g_free (src->dialin_url);

  G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void
pex_rtmp_server_src_class_init (PexRTMPServerSrcClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;
  GstBaseSrcClass *gstbasesrc_class;
  GstPushSrcClass *gstpushsrc_class;

  gobject_class = G_OBJECT_CLASS (klass);
  gstelement_class = GST_ELEMENT_CLASS (klass);
  gstbasesrc_class = GST_BASE_SRC_CLASS (klass);
  gstpushsrc_class = GST_PUSH_SRC_CLASS (klass);

  gobject_class->finalize = pex_rtmp_server_src_finalize;
  gobject_class->set_property = pex_rtmp_server_src_set_property;
  gobject_class->get_property = pex_rtmp_server_src_get_property;

  gstbasesrc_class->start = GST_DEBUG_FUNCPTR (pex_rtmp_server_src_start);
  gstbasesrc_class->stop = GST_DEBUG_FUNCPTR (pex_rtmp_server_src_stop);
  gstbasesrc_class->unlock = GST_DEBUG_FUNCPTR (pex_rtmp_server_src_unlock);
  gstpushsrc_class->create = GST_DEBUG_FUNCPTR (pex_rtmp_server_src_create);

  g_object_class_install_property (gobject_class, PROP_SERVER,
      g_param_spec_object ("server", "RTMP Server",
          "The Pex RTMP server to use", PEX_TYPE_RTMP_SERVER,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_PATH,
      g_param_spec_string ("path", "RTMP Path",
          "The path to use towards the server",
          NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_DIALIN_URL,
      g_param_spec_string ("dialin-url", "RTMP Dialin URL",
          "The RTMP URL to subscribe to",
          NULL, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_BYTES_RECEIVED,
      g_param_spec_uint ("bytes-received", "Bytes Received",
          "Number of bytes received", 0, G_MAXUINT, 0,
          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_PACKETS_RECEIVED,
      g_param_spec_uint ("packets-recevied", "Packets Received",
          "Number of packets received", 0, G_MAXUINT, 0,
          G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  gst_element_class_set_static_metadata (gstelement_class,
      "RTMP output src",
      "Src/Network", "Reads FLV content from the Pex RTMP Server",
      "Havard Graff <havard@pexip.com>");

  gst_element_class_add_static_pad_template (gstelement_class, &src_template);

  GST_DEBUG_CATEGORY_INIT (pex_rtmp_server_src_debug, "rtmpserversrc", 0,
      "RTMP server element");
}

static void
pex_rtmp_server_src_init (PexRTMPServerSrc * src)
{
  (void) src;
}
