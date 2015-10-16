/*
 * RTMPServer
 *
 * Copyright 2011 Janne Kulmala <janne.t.kulmala@iki.fi>
 * Copyright 2014 Pexip         <pexip.com>
 *
 * Program code is licensed with GNU LGPL 2.1. See COPYING.LGPL file.
 */

#include "rtmpserver.h"

#include <gst/gst.h>
#include "client.h"
#include "rtmp.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#if defined(HOST_LINUX)
#  include <linux/sockios.h>
#endif

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// GOBJECT Stuff
GST_DEBUG_CATEGORY (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

G_DEFINE_TYPE (PexRtmpServer, pex_rtmp_server, G_TYPE_OBJECT)

#define PEX_RTMP_SERVER_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj),\
      PEX_TYPE_RTMP_SERVER, PexRtmpServerPrivate))

#define DEFAULT_APPLICATION_NAME ""
#define DEFAULT_PORT 1935
#define DEFAULT_SSL_PORT 443
#define DEFAULT_CERT_FILE ""
#define DEFAULT_KEY_FILE ""
#define DEFAULT_SSL3_ENABLED FALSE
#define DEFAULT_CA_CERT_FILE ""
#define DEFAULT_CA_CERT_DIR ""
#define DEFAULT_CIPHERS "!eNULL:!aNULL:!EXP:!DES:!RC4:!RC2:!IDEA:!ADH:ALL@STRENGTH"
#define DEFAULT_STREAM_ID 1337
#define DEFAULT_CHUNK_SIZE 128
#define DEFAULT_TCP_SYNCNT -1

enum
{
  PROP_0,
  PROP_APPLICATION_NAME,
  PROP_PORT,
  PROP_SSL_PORT,
  PROP_CERT_FILE,
  PROP_KEY_FILE,
  PROP_CA_CERT_FILE,
  PROP_CA_CERT_DIR,
  PROP_CIPHERS,
  PROP_SSL3_ENABLED,
  PROP_STREAM_ID,
  PROP_CHUNK_SIZE,
  PROP_TCP_SYNCNT,
};

enum
{
  SIGNAL_ON_PLAY,
  SIGNAL_ON_PLAY_DONE,
  SIGNAL_ON_PUBLISH,
  SIGNAL_ON_PUBLISH_DONE,
  SIGNAL_ON_QUEUE_OVERFLOW,
  LAST_SIGNAL
};

static guint pex_rtmp_server_signals[LAST_SIGNAL] = { 0 };

struct _PexRtmpServerPrivate
{
  gchar * application_name;
  gint port;
  gint ssl_port;
  gchar * cert_file;
  gchar * key_file;
  gchar * ca_cert_file;
  gchar * ca_cert_dir;
  gchar * ciphers;
  gboolean ssl3_enabled;
  gint stream_id;
  gint chunk_size;
  gint tcp_syncnt;

  gint listen_fd;
  gint listen_ssl_fd;

  GArray * poll_table;
  GHashTable * fd_to_client;
  gboolean running;
  GThread * thread;
  GTimer * last_queue_overflow;

  Connections * connections;
  GstAtomicQueue * dialout_clients;
};


PexRtmpServer *
pex_rtmp_server_new (const gchar * application_name, gint port, gint ssl_port,
    const gchar * cert_file, const gchar * key_file, const gchar * ca_cert_file,
    const gchar * ca_cert_dir, const gchar * ciphers, gboolean ssl3_enabled)
{
  return g_object_new (PEX_TYPE_RTMP_SERVER,
      "application-name", application_name,
      "port", port,
      "ssl-port", ssl_port,
      "cert-file", cert_file,
      "key-file", key_file,
      "ca-cert-file", ca_cert_file,
      "ca-cert-dir", ca_cert_dir,
      "ciphers", ciphers,
      "ssl3-enabled", ssl3_enabled,
      NULL);
}

void
pex_rtmp_server_connect_signal (PexRtmpServer * srv,
    gchar * signal_name, gboolean (*callback)(gchar * path))
{
  g_signal_connect(srv, signal_name, G_CALLBACK (callback), NULL);
}

static void
pex_rtmp_server_init (PexRtmpServer *srv)
{
  PexRtmpServerPrivate * priv;
  priv = srv->priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);
  priv->application_name = NULL;
  priv->port = DEFAULT_PORT;
  priv->ssl_port = DEFAULT_SSL_PORT;
  priv->cert_file = NULL;
  priv->key_file = NULL;
  priv->ca_cert_file = NULL;
  priv->ca_cert_dir = NULL;
  priv->ciphers = NULL;
  priv->ssl3_enabled = DEFAULT_SSL3_ENABLED;

  priv->thread = NULL;
  priv->last_queue_overflow = NULL;

  priv->poll_table = g_array_new (TRUE, TRUE, sizeof (struct pollfd));
  priv->fd_to_client = g_hash_table_new (NULL, NULL);
  priv->connections = connections_new ();
  priv->dialout_clients = gst_atomic_queue_new (0);
}

static void
pex_rtmp_server_dispose (GObject * obj)
{
  G_OBJECT_CLASS (pex_rtmp_server_parent_class)->dispose (obj);
}

static void
pex_rtmp_server_finalize (GObject * obj)
{
  PexRtmpServer * srv = PEX_RTMP_SERVER_CAST (obj);
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  g_free (priv->application_name);
  g_free (priv->cert_file);
  g_free (priv->key_file);
  g_free (priv->ca_cert_file);
  g_free (priv->ca_cert_dir);
  g_free (priv->ciphers);

  g_array_free (priv->poll_table, TRUE);
  g_hash_table_destroy (priv->fd_to_client);
  connections_free (priv->connections);
  gst_atomic_queue_unref (priv->dialout_clients);

  G_OBJECT_CLASS (pex_rtmp_server_parent_class)->finalize (obj);
}

static void
pex_rtmp_server_set_property (GObject * obj, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  PexRtmpServer * srv = PEX_RTMP_SERVER_CAST (obj);

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      srv->priv->application_name = g_value_dup_string (value);
      break;
    case PROP_PORT:
      srv->priv->port = g_value_get_int (value);
      break;
    case PROP_SSL_PORT:
      srv->priv->ssl_port = g_value_get_int (value);
      break;
    case PROP_CERT_FILE:
      srv->priv->cert_file = g_value_dup_string (value);
      break;
    case PROP_KEY_FILE:
      srv->priv->key_file = g_value_dup_string (value);
      break;
    case PROP_CA_CERT_FILE:
      srv->priv->ca_cert_file = g_value_dup_string (value);
      break;
    case PROP_CA_CERT_DIR:
      srv->priv->ca_cert_dir = g_value_dup_string (value);
      break;
    case PROP_CIPHERS:
      srv->priv->ciphers = g_value_dup_string (value);
      break;
    case PROP_SSL3_ENABLED:
      srv->priv->ssl3_enabled = g_value_get_boolean (value);
      break;
    case PROP_STREAM_ID:
      srv->priv->stream_id = g_value_get_int (value);
      break;
    case PROP_CHUNK_SIZE:
      srv->priv->chunk_size = g_value_get_int (value);
      break;
    case PROP_TCP_SYNCNT:
      srv->priv->tcp_syncnt = g_value_get_int (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
  }
}

static void
pex_rtmp_server_get_property (GObject * obj, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  PexRtmpServer * srv = PEX_RTMP_SERVER_CAST (obj);

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      g_value_set_string (value, srv->priv->application_name);
      break;
    case PROP_PORT:
      g_value_set_int (value, srv->priv->port);
      break;
    case PROP_SSL_PORT:
      g_value_set_int (value, srv->priv->ssl_port);
      break;
    case PROP_CERT_FILE:
      g_value_set_string (value, srv->priv->cert_file);
      break;
    case PROP_KEY_FILE:
      g_value_set_string (value, srv->priv->key_file);
      break;
    case PROP_CA_CERT_FILE:
      g_value_set_string (value, srv->priv->ca_cert_file);
      break;
    case PROP_CA_CERT_DIR:
      g_value_set_string (value, srv->priv->ca_cert_dir);
      break;
    case PROP_CIPHERS:
      g_value_set_string (value, srv->priv->ciphers);
      break;
    case PROP_SSL3_ENABLED:
      g_value_set_boolean (value, srv->priv->ssl3_enabled);
      break;
    case PROP_STREAM_ID:
      g_value_set_int (value, srv->priv->stream_id);
      break;
    case PROP_CHUNK_SIZE:
      g_value_set_int (value, srv->priv->chunk_size);
      break;
    case PROP_TCP_SYNCNT:
      g_value_set_int (value, srv->priv->tcp_syncnt);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
  }
}

static void
pex_rtmp_server_class_init (PexRtmpServerClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS (klass);

  gobject_class->set_property = pex_rtmp_server_set_property;
  gobject_class->get_property = pex_rtmp_server_get_property;
  gobject_class->dispose = pex_rtmp_server_dispose;
  gobject_class->finalize = pex_rtmp_server_finalize;

  g_object_class_install_property (gobject_class, PROP_APPLICATION_NAME,
      g_param_spec_string ("application-name", "Application Name",
          "The application name for this server", DEFAULT_APPLICATION_NAME,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_PORT,
      g_param_spec_int ("port", "Port",
          "The port to listen on", 0, 65535, DEFAULT_PORT,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_SSL_PORT,
      g_param_spec_int ("ssl-port", "Port",
          "The port to listen on", 0, 65535, DEFAULT_SSL_PORT,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_CERT_FILE,
      g_param_spec_string ("cert-file", "Certificate file",
          "File containing TLS certificate", DEFAULT_CERT_FILE,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_KEY_FILE,
      g_param_spec_string ("key-file", "Key file",
          "File containing TLS private key", DEFAULT_KEY_FILE,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_CA_CERT_FILE,
      g_param_spec_string ("ca-cert-file", "Trusted CA file",
          "File containing trusted CA certificates", DEFAULT_CA_CERT_FILE,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_CA_CERT_DIR,
      g_param_spec_string ("ca-cert-dir", "Trusted CA dir",
          "Directory containing trusted CA certificates", DEFAULT_CA_CERT_DIR,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_CIPHERS,
      g_param_spec_string ("ciphers", "Cipher specification",
          "Specification of ciphers to use", DEFAULT_CIPHERS,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_SSL3_ENABLED,
      g_param_spec_boolean ("ssl3-enabled", "SSL3 enabled",
          "Whether SSL3 is enabled", DEFAULT_SSL3_ENABLED,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_STREAM_ID,
      g_param_spec_int ("stream-id", "Stream ID",
          "The ID to use for the RTMP Media stream",
          0, G_MAXINT, DEFAULT_STREAM_ID,
          G_PARAM_CONSTRUCT | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_CHUNK_SIZE,
      g_param_spec_int ("chunk-size", "Chunk Size",
          "The chunk size to advertise for RTMP packets",
          0, G_MAXINT, DEFAULT_CHUNK_SIZE,
          G_PARAM_CONSTRUCT | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_TCP_SYNCNT,
      g_param_spec_int ("tcp-syncnt", "TCP SYNCNT",
          "The maximum number of TCP SYN retransmits",
          -1, 255, DEFAULT_TCP_SYNCNT,
          G_PARAM_CONSTRUCT | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  pex_rtmp_server_signals[SIGNAL_ON_PLAY] =
      g_signal_new ("on-play", PEX_TYPE_RTMP_SERVER,
      G_SIGNAL_RUN_LAST, 0, NULL, NULL, g_cclosure_marshal_generic,
      G_TYPE_BOOLEAN, 1, G_TYPE_STRING);

  pex_rtmp_server_signals[SIGNAL_ON_PLAY_DONE] =
      g_signal_new ("on-play-done", PEX_TYPE_RTMP_SERVER,
          G_SIGNAL_RUN_LAST, 0, NULL, NULL, g_cclosure_marshal_generic,
          G_TYPE_NONE, 1, G_TYPE_STRING);

  pex_rtmp_server_signals[SIGNAL_ON_PUBLISH] =
      g_signal_new ("on-publish", PEX_TYPE_RTMP_SERVER,
          G_SIGNAL_RUN_LAST, 0, NULL, NULL, g_cclosure_marshal_generic,
          G_TYPE_BOOLEAN, 1, G_TYPE_STRING);

  pex_rtmp_server_signals[SIGNAL_ON_PUBLISH_DONE] =
      g_signal_new ("on-publish-done", PEX_TYPE_RTMP_SERVER,
          G_SIGNAL_RUN_LAST, 0, NULL, NULL, g_cclosure_marshal_generic,
          G_TYPE_NONE, 1, G_TYPE_STRING);

  pex_rtmp_server_signals[SIGNAL_ON_QUEUE_OVERFLOW] =
      g_signal_new ("on-queue-overflow", PEX_TYPE_RTMP_SERVER,
          G_SIGNAL_RUN_LAST, 0, NULL, NULL, g_cclosure_marshal_generic,
          G_TYPE_NONE, 1, G_TYPE_STRING);

  g_type_class_add_private (gobject_class, sizeof (PexRtmpServerPrivate));

  GST_DEBUG_CATEGORY_INIT (
    pex_rtmp_server_debug, "pexrtmpserver", 0, "pexrtmpserver");
}

static int
set_nonblock (int fd, gboolean enabled)
{
  int flags = fcntl (fd, F_GETFL) & ~O_NONBLOCK;
  if (enabled) {
    flags |= O_NONBLOCK;
  }
  return fcntl (fd, F_SETFL, flags);
}

static void
pex_rtmp_server_add_fd_to_poll_table (PexRtmpServer * srv, gint fd)
{
  struct pollfd entry;
  entry.events = POLLIN;
  entry.revents = 0;
  entry.fd = fd;
  srv->priv->poll_table = g_array_append_val (srv->priv->poll_table, entry);

  GST_DEBUG_OBJECT (srv, "Added fd %d to poll-table", fd);
}

static void
rtmp_server_add_client_to_poll_table (PexRtmpServer * srv, Client * client)
{
  /* create a poll entry, and link it to the client */
  gint fd = client->fd;
  pex_rtmp_server_add_fd_to_poll_table (srv, fd);
  g_hash_table_insert (srv->priv->fd_to_client, GINT_TO_POINTER (fd), client);
  client->added_to_fd_table = TRUE;
}

static void
rtmp_server_create_client (PexRtmpServer * srv, gint listen_fd)
{
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof (sin);
  gint fd = accept (listen_fd, (struct sockaddr *)&sin, &addrlen);
  if (fd < 0) {
    GST_WARNING_OBJECT (srv, "Unable to accept a client on fd %d: %s", listen_fd, strerror (errno));
    return;
  }

  /* make the connection non-blocking */
  set_nonblock (fd, TRUE);

  gboolean use_ssl = listen_fd == srv->priv->listen_ssl_fd;
  GST_INFO_OBJECT (srv, "Accepted client %s connection using port %d", use_ssl ? "rtmps" : "rtmp", 
                    ntohs(sin.sin_port));
  Client * client = client_new (fd, srv->priv->connections, G_OBJECT (srv),
      use_ssl, srv->priv->stream_id, srv->priv->chunk_size, NULL);

  /* ssl connection */
  if (use_ssl) {
    gchar * cert_file, * key_file, * ca_file, * ca_dir, * ciphers;
    gboolean ssl3_enabled;

    g_object_get (srv,
                  "cert-file", &cert_file,
                  "key-file", &key_file,
                  "ca-cert-file", &ca_file,
                  "ca-cert-dir", &ca_dir,
                  "ciphers", &ciphers,
                  "ssl3-enabled", &ssl3_enabled,
                  NULL);

    client_add_incoming_ssl (client, cert_file, key_file, ca_file, ca_dir, ciphers, ssl3_enabled);

    g_free (cert_file);
    g_free (key_file);
    g_free (ca_file);
    g_free (ca_dir);
    g_free (ciphers);
  }

  rtmp_server_add_client_to_poll_table (srv, client);

  GST_DEBUG_OBJECT (srv, "adding client %p to fd %d", client, fd);
}

static Client *
rtmp_server_create_dialout_client (PexRtmpServer * srv, gint fd,
    const gchar * path, const gchar * protocol, const gchar * remote_host,
    const gchar * tcUrl, const gchar * app, const gchar * dialout_path,
    const gchar * url, const gchar * addresses, const gboolean is_publisher)
{
  gboolean use_ssl = (g_strcmp0 (protocol, "rtmps") == 0);

  GST_DEBUG_OBJECT (srv, "Initiating a %s connection", protocol);
  Client * client = client_new (fd, srv->priv->connections, G_OBJECT (srv),
      use_ssl, srv->priv->stream_id, srv->priv->chunk_size, remote_host);
  client->path = g_strdup (path);
  client->dialout_path = g_strdup (dialout_path);
  client->tcUrl = g_strdup (tcUrl);
  client->app = g_strdup (app);
  client->url = g_strdup (url);
  client->publisher = is_publisher;
  client->addresses = g_strdup (addresses);

  if (use_ssl) {
    gchar * ca_file, * ca_dir, * ciphers;
    gboolean ssl3_enabled;

    g_object_get (srv,
                  "ca-cert-file", &ca_file,
                  "ca-cert-dir", &ca_dir,
                  "ciphers", &ciphers,
                  "ssl3-enabled", &ssl3_enabled,
                  NULL);

    if (!client_add_outgoing_ssl (client, ca_file, ca_dir, ciphers, ssl3_enabled)) {
      /* Client logs warnings for us, so no need to do that here */
      g_free (ca_file);
      g_free (ca_dir);
      g_free (ciphers);
      client_free (client);
      return NULL;
    }

    g_free (ca_file);
    g_free (ca_dir);
    g_free (ciphers);
  }

  return client;
}

static void
rtmp_server_remove_client (PexRtmpServer * srv, Client * client)
{
  GST_DEBUG_OBJECT (srv, "removing client %p with fd %d", client, client->fd);
  if (client->added_to_fd_table)
    g_assert (g_hash_table_remove (srv->priv->fd_to_client, GINT_TO_POINTER (client->fd)));
  if (!client->released) {
    close (client->fd);
    client->released = TRUE;
  }

  if (client->path)
    connections_remove_client (srv->priv->connections, client, client->path);

  gchar * path = g_strdup (client->path);
  gboolean publisher = client->publisher;
  client_free (client);

  if (srv->priv->running) {
    if (publisher) {
      g_signal_emit (srv,
          pex_rtmp_server_signals[SIGNAL_ON_PUBLISH_DONE], 0, path);
    } else {
      g_signal_emit (srv,
          pex_rtmp_server_signals[SIGNAL_ON_PLAY_DONE], 0, path);
    }
  }

  if (publisher) {
    GSList * subscribers = connections_get_subscribers (
        srv->priv->connections, path);
    for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
      Client * subscriber = (Client *)walk->data;
      GST_DEBUG_OBJECT (srv,
          "removing streaming subscriber %p as publisher removed with fd %d",
          subscriber, subscriber->fd);
      if (subscriber->dialout_path) {
        close (subscriber->fd);
        subscriber->released = TRUE;
      }
    }
  }

  g_free (path);
}

#if defined(HOST_LINUX)
static void
rtmp_server_update_send_queues (PexRtmpServer * srv, Client * client)
{
  int val, error;

  error = ioctl (client->fd, SIOCOUTQ, &val);
  if (error)
    val = 0;

  gboolean decreasing = (val - client->write_queue_size < 0);
  client->write_queue_size = val;
  if (!decreasing && client->write_queue_size > 75000) {
    if (srv->priv->last_queue_overflow == NULL) {
      srv->priv->last_queue_overflow = g_timer_new ();
    }
    guint elapsed = g_timer_elapsed (srv->priv->last_queue_overflow, NULL);
    if (elapsed >= 2) {
      GST_DEBUG_OBJECT (srv,
          "(%s) Emitting signal on-queue-overflow due to %d bytes in queue",
          client->path,val);
      g_signal_emit (srv, pex_rtmp_server_signals[SIGNAL_ON_QUEUE_OVERFLOW],
          0, client->path);
      g_timer_start (srv->priv->last_queue_overflow);
    }
  }
}
#endif


static gint
count_chars_in_string (const gchar * s, char c)
{
  gint ret;
  for (ret = 0; s[ret]; s[ret]==c ? ret++ : *(s++));
  return ret;
}

static gboolean
get_port_from_string (const gchar * s, gint * port)
{
  if (s) {
    if (strlen (s) > 0) {
      *port = atoi (s);
    } else {
      return FALSE;
    }
  } else {
    *port = 1935;
  }
  return TRUE;
}

void
pex_rtmp_server_get_application_for_path (PexRtmpServer * srv, gchar * path, gboolean is_publisher, gchar ** application) {
  Client * connection = NULL;
  GST_WARNING_OBJECT (srv, "Finding application for %s - publish: %d", path, is_publisher);
  GList * clients = g_hash_table_get_values (srv->priv->fd_to_client);
  for (GList * walk = clients; walk; walk = g_list_next (walk)) {
    Client * client = (Client *)walk->data;
    if (g_strcmp0 (client->path, path) == 0 && client->publisher == is_publisher) {
      connection = client;
      break;
    }
  }
  g_list_free (clients);
  if (connection != NULL) {
    *application = connection->app;
  } else {
    *application = NULL;
  }
}

gboolean
pex_rtmp_server_parse_url (PexRtmpServer * srv, const gchar * url,
    gchar ** protocol, gint * port, gchar ** ip, gchar ** application_name,
    gchar ** path)
{
  gboolean ret = TRUE;

  gchar ** space_clip = NULL;
  gchar ** protocol_clip = NULL;
  gchar ** slash_clip = NULL;
  gchar ** address_clip = NULL;

  *protocol = NULL;
  *port = 0;
  *ip = NULL;
  *application_name = NULL;
  *path = NULL;

  /* start by clipping off anything on the end (live=1) */
  space_clip = g_strsplit (url, " ", 1024);
  const gchar * url_nospace = space_clip[0];

  if (url_nospace == NULL) {
    GST_WARNING_OBJECT (srv, "Unable to parse");
    ret = FALSE;
    goto done;
  }

  /* then clip before and after protocol (rtmp://) */
  protocol_clip = g_strsplit (url_nospace, "://", 1024);
  const gchar * protocol_tmp = protocol_clip[0];
  const gchar * the_rest = protocol_clip[1];
  if (!(protocol_tmp && the_rest && (g_strcmp0 (protocol_tmp, "rtmp") == 0 || g_strcmp0 (protocol_tmp, "rtmps") == 0))) {
    GST_WARNING_OBJECT (srv, "Unable to parse");
    ret = FALSE;
    goto done;
  }

  /* clip all "/" bits */
  slash_clip = g_strsplit (the_rest, "/", 1024);
  gint idx = 0;
  while (slash_clip[idx] != NULL)
    idx++;
  if (idx < 3) {
    GST_WARNING_OBJECT (srv, "Not able to find address, application_name and path");
    ret = FALSE;
    goto done;
  }

  /* clip IP and port */
  const gchar * address = slash_clip[0];
  gint num_colons = count_chars_in_string (address, ':');
  if (num_colons > 1) { /* ipv6 */
    address_clip = g_strsplit (address, "]:", 1024);

    if (!get_port_from_string (address_clip[1], port)) {
      GST_WARNING_OBJECT (srv, "Specify the port, buster!");
      ret = FALSE;
      goto done;
    }

    if (address_clip[1] != NULL) {
      *ip = g_strdup (&address_clip[0][1]); /* remove the the beginning '[' */
    } else {
      *ip = g_strdup (address);
    }
  } else { /* ipv4 */
    address_clip = g_strsplit (address, ":", 1024);
    if (!get_port_from_string (address_clip[1], port)) {
      GST_WARNING_OBJECT (srv, "Specify the port, buster!");
      ret = FALSE;
      goto done;
    }
    *ip = g_strdup (address_clip[0]);
  }

  *protocol = g_strdup (protocol_tmp);
  *path = g_strdup (slash_clip[idx - 1]); /* path is last */
  *application_name = g_strndup (&the_rest[strlen (address) + 1],
      strlen (the_rest) - strlen (address) - strlen (*path) - 2);

  GST_DEBUG_OBJECT (srv, "Parsed: Protocol: %s, Ip: %s, Port: %d, Application Name: %s, Path: %s",
      *protocol, *ip, *port, *application_name, *path);

done:
  g_strfreev (space_clip);
  g_strfreev (protocol_clip);
  g_strfreev (slash_clip);
  g_strfreev (address_clip);

  return ret;
}

#define INVALID_FD -1
gint
pex_rtmp_server_tcp_connect (PexRtmpServer * srv,
    const gchar * ip, gint port)
{
  int ret;
  int fd;
  struct sockaddr_storage address;

  memset (&address, 0, sizeof(struct sockaddr_storage));

  struct addrinfo hints;
  struct addrinfo *result = NULL;

  memset (&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM; /* Stream soc */
  hints.ai_protocol = IPPROTO_TCP; /* TCP protocol */

  ret = getaddrinfo (ip, NULL, &hints, &result);
  if (ret != 0) {
    GST_WARNING_OBJECT (srv, "getaddrinfo: %s", gai_strerror(ret));
    return INVALID_FD;
  }
  memcpy (&address, result->ai_addr, result->ai_addrlen);
  freeaddrinfo (result);

  fd = socket (address.ss_family, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    GST_WARNING_OBJECT (srv, "could not create soc: %s", g_strerror (errno));
    return INVALID_FD;
  }

  /* make the connection non-blocking */
  set_nonblock (fd, TRUE);

  /* set timeout */
  struct timeval tv = {30, 0};
  if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof (tv))) {
    GST_WARNING_OBJECT (srv, "Could not set timeout");
  }

  /* Disable packet-accumulation delay (Nagle's algorithm) */
  gint value = 1;
  setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (char *)&value, sizeof (value));

  /* Configure TCP_SYNCNT */
  if (srv->priv->tcp_syncnt >= 0) {
#ifdef TCP_SYNCNT
    value = srv->priv->tcp_syncnt;
    setsockopt (fd, IPPROTO_TCP, TCP_SYNCNT, (char *)&value, sizeof (value));
#endif
  }

  if (address.ss_family == AF_INET) {
    ((struct sockaddr_in *)&address)->sin_port = htons (port);
    ret = connect (fd, (struct sockaddr *)&address, sizeof (struct sockaddr_in));
  } else {
    ((struct sockaddr_in6 *)&address)->sin6_port = htons (port);
    ret = connect (fd, (struct sockaddr *)&address, sizeof (struct sockaddr_in6));
  }

  if (ret != 0 && errno != EINPROGRESS) {
      GST_WARNING_OBJECT (srv, "could not connect on port %d: %s", port, g_strerror (errno));
      close (fd);
      return INVALID_FD;
  }

  return fd;
}

gboolean
pex_rtmp_server_dialout (PexRtmpServer * srv,
    const gchar * src_path, const gchar * url, const gchar * addresses)
{
  return pex_rtmp_server_external_connect (srv, src_path, url, addresses, FALSE);
}

gboolean
pex_rtmp_server_dialin (PexRtmpServer * srv,
    const gchar * src_path, const gchar * url, const gchar * addresses)
{
  return pex_rtmp_server_external_connect (srv, src_path, url, addresses, TRUE);
}

gboolean
pex_rtmp_server_external_connect (PexRtmpServer * srv,
    const gchar * src_path, const gchar * url, const gchar * addresses, const gboolean is_publisher)
{
  gboolean ret = FALSE;
  gchar * protocol = NULL;
  gint port;
  gchar * host = NULL;
  gchar * app = NULL;
  gchar * dialout_path = NULL;
  gchar * tcUrl = NULL;
  gchar ** addressv = NULL;
  gchar ** address = NULL;
  gchar * new_addresses = NULL;
  gint fd = INVALID_FD;

  if (!pex_rtmp_server_parse_url (srv, url,
      &protocol, &port, &host, &app, &dialout_path)) {
    goto done;
  }

  if (addresses == NULL) {
    addresses = host;
  }

  addressv = g_strsplit (addresses, ",", 1024);
  if (!addressv[0]) {
    GST_WARNING_OBJECT (srv, "No more addresses");
    goto done;
  }

  for (address = addressv; *address && fd == INVALID_FD; address++) {
    fd = pex_rtmp_server_tcp_connect (srv, *address, port);
  }

  if (fd == INVALID_FD && !*address) {
    GST_WARNING_OBJECT (srv, "Not able to connect");
    goto done;
  }

  new_addresses = g_strjoinv(",", addressv+1);

  const gchar *tcUrlFmt = "%s://%s:%d/%s";
  if (strchr (host, ':')) { /* ipv6 */
    tcUrlFmt = "%s://[%s]:%d/%s";
  }
  tcUrl = g_strdup_printf (tcUrlFmt, protocol, host, port, app);

  Client * client = rtmp_server_create_dialout_client (srv, fd,
      src_path, protocol, host, tcUrl, app, dialout_path,
      url, new_addresses, is_publisher);

  if (client == NULL) {
    GST_WARNING_OBJECT (srv, "Unable to create client");
    close (fd);
    goto done;
  }

  /* add the client to the queue, waiting to be added */
  gst_atomic_queue_push (srv->priv->dialout_clients, client);
  ret = TRUE;

done:
  g_free (new_addresses);
  g_strfreev (addressv);
  g_free (tcUrl);
  g_free (protocol);
  g_free (host);
  g_free (app);
  g_free (dialout_path);

  return ret;
}

void
rtmp_server_add_pending_dialout_clients (PexRtmpServer * srv)
{
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  while (gst_atomic_queue_length (priv->dialout_clients) > 0) {
    Client * client = gst_atomic_queue_pop (priv->dialout_clients);
    rtmp_server_add_client_to_poll_table (srv, client);
    GST_DEBUG_OBJECT (srv, "adding client %p to fd %d", client, client->fd);
  }
}

static gboolean
rtmp_server_do_poll (PexRtmpServer * srv)
{
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  rtmp_server_add_pending_dialout_clients (srv);

  for (size_t i = 0; i < priv->poll_table->len; ++i) {
    struct pollfd * entry = (struct pollfd *)&g_array_index (
        priv->poll_table, struct pollfd, i);

    Client * client = g_hash_table_lookup (priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));
    if (client != NULL) {
#if defined(HOST_LINUX)
      if (!client->publisher) {
        rtmp_server_update_send_queues (srv, client);
      }
#endif
      entry->events = client_get_poll_events (client);
    }
  }

  /* waiting for traffic on all connections */
  const gint timeout = 200; /* 200 ms second */
  gint result = poll ((struct pollfd *)&priv->poll_table->data[0],
      priv->poll_table->len, timeout);

  if (priv->running == FALSE)
    return FALSE;

  if (result < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    GST_WARNING_OBJECT (srv, "poll() failed: %s", strerror (errno));
    return FALSE;
  }

  for (size_t i = 0; i < priv->poll_table->len; ++i) {
    if (priv->running == FALSE)
      return FALSE;

    struct pollfd * entry = (struct pollfd *)&g_array_index (
        priv->poll_table, struct pollfd, i);
    Client * client = g_hash_table_lookup (priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));
    //GST_DEBUG_OBJECT (srv, "fd %d has client %p", entry->fd, client);

    /* ready to send */
    if (client && entry->revents & POLLOUT) {
      gboolean connect_failed = FALSE;
      if (!client_try_to_send (client, &connect_failed)) {
        if (connect_failed && client->addresses) {
          pex_rtmp_server_external_connect (srv, client->path, client->url, client->addresses, client->publisher);
        } else {
          GST_WARNING_OBJECT (srv, "client error, send failed");
        }
        rtmp_server_remove_client (srv, client);
        srv->priv->poll_table = g_array_remove_index (priv->poll_table, i);
        i--;
        continue;
      }
    }
    /* data to receive */
    if (entry->revents & POLLIN) {
      if (client == NULL) {
        rtmp_server_create_client (srv, entry->fd);
      } else if (!client_receive (client)) {
        GST_WARNING_OBJECT (srv, "client error: client_recv_from_client failed");
        rtmp_server_remove_client (srv, client);
        priv->poll_table = g_array_remove_index (priv->poll_table, i);
        i--;
      }
    }
  }
  return TRUE;
}

static gpointer
rtmp_server_func (gpointer data)
{
  PexRtmpServer * srv = PEX_RTMP_SERVER_CAST (data);
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  gboolean ret = TRUE;
  signal (SIGPIPE, SIG_IGN);

  while (srv->priv->running && ret) {
    ret = rtmp_server_do_poll (srv);
  }

  /* remove outstanding clients */
  for (size_t i = 0; i < srv->priv->poll_table->len; ++i) {
    struct pollfd * entry = (struct pollfd *)&g_array_index (
        priv->poll_table, struct pollfd, i);
    Client * client = g_hash_table_lookup (priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));
    if (client)
      rtmp_server_remove_client (srv, client);
    priv->poll_table = g_array_remove_index (priv->poll_table, i);
    i--;
  }

  while (gst_atomic_queue_length (priv->dialout_clients) > 0) {
    Client * client = gst_atomic_queue_pop (priv->dialout_clients);
    rtmp_server_remove_client (srv, client);
  }

  return NULL;
}

gint
pex_rtmp_server_add_listen_fd (PexRtmpServer * srv, gint port)
{
  gint fd = socket (AF_INET6, SOCK_STREAM, 0);
  g_assert_cmpint (fd, >=, 0);

  int sock_optval = 1;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR,
      &sock_optval, sizeof (sock_optval));

  struct sockaddr_in6 sin;
  memset (&sin, 0, sizeof (struct sockaddr_in6));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = htons (port);
  sin.sin6_addr = in6addr_any;

  if (bind (fd, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
    GST_WARNING_OBJECT (srv, "Unable to listen to port %d: %s",
        port, strerror (errno));
    close (fd);
    return -1;
  }

  listen (fd, 10);
  GST_DEBUG_OBJECT (srv, "Listening on port %d with fd %d", port, fd);

  return fd;
}

gboolean
pex_rtmp_server_start (PexRtmpServer * srv)
{
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  /* listen for normal and ssl connections */
  priv->listen_fd = pex_rtmp_server_add_listen_fd (srv, priv->port);
  if (priv->listen_fd <= 0)
    return FALSE;
  priv->listen_ssl_fd = pex_rtmp_server_add_listen_fd (srv, priv->ssl_port);
  if (priv->listen_ssl_fd <= 0)
    return FALSE;

  /* add fds to poll table */
  pex_rtmp_server_add_fd_to_poll_table (srv, priv->listen_fd);
  pex_rtmp_server_add_fd_to_poll_table (srv, priv->listen_ssl_fd);

  priv->running = TRUE;
  priv->thread = g_thread_new ("RTMPServer", rtmp_server_func, srv);

  return TRUE;
}

void
pex_rtmp_server_stop (PexRtmpServer * srv)
{
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  GST_DEBUG_OBJECT (srv, "Stopping...");
  priv->running = FALSE;
  if (priv->thread)
    g_thread_join (priv->thread);

  if (priv->last_queue_overflow != NULL) {
    g_timer_destroy (priv->last_queue_overflow);
  }
  if (priv->listen_fd > 0)
    close (priv->listen_fd);
  if (priv->listen_ssl_fd > 0)
    close (priv->listen_ssl_fd);
}

void pex_rtmp_server_free (PexRtmpServer * srv)
{
  g_object_unref (srv);
}
