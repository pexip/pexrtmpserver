/*
 * RTMPServer
 *
 * Copyright 2011 Janne Kulmala <janne.t.kulmala@iki.fi>
 * Copyright 2014 Pexip         <pexip.com>
 *
 * Program code is licensed with GNU LGPL 2.1. See COPYING.LGPL file.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rtmpserver.h"

#include <gst/gst.h>
#include "client.h"
#include "rtmp.h"
#include "utils.h"

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
#define DEFAULT_TLS1_ENABLED FALSE
#define DEFAULT_IGNORE_LOCALHOST FALSE
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
  PROP_TLS1_ENABLED,
  PROP_IGNORE_LOCALHOST,
  PROP_STREAM_ID,
  PROP_CHUNK_SIZE,
  PROP_TCP_SYNCNT,
  PROP_POLL_COUNT,
  PROP_USERNAME,
  PROP_PASSWORD,
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
  gchar *application_name;
  gint port;
  gint ssl_port;
  gchar *cert_file;
  gchar *key_file;
  gchar *ca_cert_file;
  gchar *ca_cert_dir;
  gchar *ciphers;
  gboolean tls1_enabled;
  gboolean ignore_localhost;
  gint stream_id;
  gint chunk_size;
  gint tcp_syncnt;
  gint poll_count;

  gchar *username;
  gchar *password;
  gchar *opaque;
  gchar *salt;

  gint listen_fd;
  gint listen_ssl_fd;

  GArray *poll_table;
  GHashTable *fd_to_client;
  gboolean running;
  GThread *thread;

  Connections *connections;
  GstAtomicQueue *dialout_clients;
};


PexRtmpServer *
pex_rtmp_server_new (const gchar * application_name, gint port, gint ssl_port,
    const gchar * cert_file, const gchar * key_file, const gchar * ca_cert_file,
    const gchar * ca_cert_dir, const gchar * ciphers, gboolean tls1_enabled,
    gboolean ignore_localhost)
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
      "tls1-enabled", tls1_enabled, "ignore-localhost", ignore_localhost, NULL);
}

static void
pex_rtmp_server_init (PexRtmpServer * srv)
{
  PexRtmpServerPrivate *priv;
  priv = srv->priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);
  priv->application_name = NULL;
  priv->port = DEFAULT_PORT;
  priv->ssl_port = DEFAULT_SSL_PORT;
  priv->cert_file = NULL;
  priv->key_file = NULL;
  priv->ca_cert_file = NULL;
  priv->ca_cert_dir = NULL;
  priv->ciphers = NULL;
  priv->tls1_enabled = DEFAULT_TLS1_ENABLED;
  priv->ignore_localhost = DEFAULT_IGNORE_LOCALHOST;

  priv->thread = NULL;

  priv->poll_table = g_array_new (TRUE, TRUE, sizeof (struct pollfd));
  priv->fd_to_client = g_hash_table_new (NULL, NULL);
  priv->connections = connections_new ();
  priv->dialout_clients = gst_atomic_queue_new (0);

  /* FIXME: only need to generate this when username and password is set */
  guint32 rand_data = g_random_int();
  priv->opaque = g_base64_encode ((guchar *)&rand_data, sizeof (guint32));
  rand_data = g_random_int();
  priv->salt = g_base64_encode ((guchar *)&rand_data, sizeof (guint32));
}

static void
pex_rtmp_server_dispose (GObject * obj)
{
  G_OBJECT_CLASS (pex_rtmp_server_parent_class)->dispose (obj);
}

static void
pex_rtmp_server_finalize (GObject * obj)
{
  PexRtmpServer *srv = PEX_RTMP_SERVER_CAST (obj);
  PexRtmpServerPrivate *priv = srv->priv;

  g_free (priv->application_name);
  g_free (priv->cert_file);
  g_free (priv->key_file);
  g_free (priv->ca_cert_file);
  g_free (priv->ca_cert_dir);
  g_free (priv->ciphers);
  g_free (priv->opaque);
  g_free (priv->salt);
  g_free (priv->username);
  g_free (priv->password);

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
  PexRtmpServer *srv = PEX_RTMP_SERVER_CAST (obj);
  PexRtmpServerPrivate *priv = srv->priv;

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      priv->application_name = g_value_dup_string (value);
      break;
    case PROP_PORT:
      priv->port = g_value_get_int (value);
      break;
    case PROP_SSL_PORT:
      priv->ssl_port = g_value_get_int (value);
      break;
    case PROP_CERT_FILE:
      priv->cert_file = g_value_dup_string (value);
      break;
    case PROP_KEY_FILE:
      priv->key_file = g_value_dup_string (value);
      break;
    case PROP_CA_CERT_FILE:
      priv->ca_cert_file = g_value_dup_string (value);
      break;
    case PROP_CA_CERT_DIR:
      priv->ca_cert_dir = g_value_dup_string (value);
      break;
    case PROP_CIPHERS:
      priv->ciphers = g_value_dup_string (value);
      break;
    case PROP_TLS1_ENABLED:
      priv->tls1_enabled = g_value_get_boolean (value);
      break;
    case PROP_IGNORE_LOCALHOST:
      priv->ignore_localhost = g_value_get_boolean (value);
      break;
    case PROP_STREAM_ID:
      priv->stream_id = g_value_get_int (value);
      break;
    case PROP_CHUNK_SIZE:
      priv->chunk_size = g_value_get_int (value);
      break;
    case PROP_TCP_SYNCNT:
      priv->tcp_syncnt = g_value_get_int (value);
      break;
    case PROP_USERNAME:
      g_free (priv->username);
      priv->username = g_value_dup_string (value);
      break;
    case PROP_PASSWORD:
      g_free (priv->password);
      priv->password = g_value_dup_string (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
  }
}

static void
pex_rtmp_server_get_property (GObject * obj, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  PexRtmpServer *srv = PEX_RTMP_SERVER_CAST (obj);
  PexRtmpServerPrivate *priv = srv->priv;

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      g_value_set_string (value, priv->application_name);
      break;
    case PROP_PORT:
      g_value_set_int (value, priv->port);
      break;
    case PROP_SSL_PORT:
      g_value_set_int (value, priv->ssl_port);
      break;
    case PROP_CERT_FILE:
      g_value_set_string (value, priv->cert_file);
      break;
    case PROP_KEY_FILE:
      g_value_set_string (value, priv->key_file);
      break;
    case PROP_CA_CERT_FILE:
      g_value_set_string (value, priv->ca_cert_file);
      break;
    case PROP_CA_CERT_DIR:
      g_value_set_string (value, priv->ca_cert_dir);
      break;
    case PROP_CIPHERS:
      g_value_set_string (value, priv->ciphers);
      break;
    case PROP_TLS1_ENABLED:
      g_value_set_boolean (value, priv->tls1_enabled);
      break;
    case PROP_IGNORE_LOCALHOST:
      g_value_set_boolean (value, priv->ignore_localhost);
      break;
    case PROP_STREAM_ID:
      g_value_set_int (value, priv->stream_id);
      break;
    case PROP_CHUNK_SIZE:
      g_value_set_int (value, priv->chunk_size);
      break;
    case PROP_TCP_SYNCNT:
      g_value_set_int (value, priv->tcp_syncnt);
      break;
    case PROP_POLL_COUNT:
      g_value_set_int (value, priv->poll_count);
      break;
    case PROP_USERNAME:
      g_value_set_string (value, priv->username);
      break;
    case PROP_PASSWORD:
      g_value_set_string (value, priv->password);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
  }
}

static void
pex_rtmp_server_class_init (PexRtmpServerClass * klass)
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

  g_object_class_install_property (gobject_class, PROP_TLS1_ENABLED,
      g_param_spec_boolean ("tls1-enabled", "TLS1 enabled",
          "Whether TLS1 is enabled", DEFAULT_TLS1_ENABLED,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_IGNORE_LOCALHOST,
      g_param_spec_boolean ("ignore-localhost",
          "Localhost ignored from signal emitting",
          "Localhost ignored from signal emitting", DEFAULT_IGNORE_LOCALHOST,
          G_PARAM_CONSTRUCT | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

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

  g_object_class_install_property (gobject_class, PROP_POLL_COUNT,
      g_param_spec_int ("poll-count", "Poll count",
          "The number of times poll() has been called",
          0, G_MAXINT, 0, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_USERNAME,
      g_param_spec_string ("username", "Username",
          "The username needed to publish to this server", NULL,
          G_PARAM_CONSTRUCT | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_PASSWORD,
      g_param_spec_string ("password", "Password",
          "The password needed to publish to this server", NULL,
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

  GST_DEBUG_CATEGORY_INIT (pex_rtmp_server_debug, "pexrtmpserver", 0,
      "pexrtmpserver");
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
  PexRtmpServerPrivate *priv = srv->priv;

  struct sockaddr_in sin;
  socklen_t addrlen = sizeof (sin);
  gint fd = accept (listen_fd, (struct sockaddr *) &sin, &addrlen);
  if (fd < 0) {
    GST_WARNING_OBJECT (srv, "Unable to accept a client on fd %d: %s",
        listen_fd, strerror (errno));
    return;
  }

  /* make the connection non-blocking */
  tcp_set_nonblock (fd, TRUE);

  gboolean use_ssl = listen_fd == priv->listen_ssl_fd;
  Client *client = client_new (G_OBJECT (srv), priv->connections,
      priv->ignore_localhost, priv->stream_id,
      priv->chunk_size);

  /* FIXME: pass with functions instead */
  client->fd = fd;
  client->use_ssl = use_ssl;
  client->username = g_strdup (priv->username);
  client->password = g_strdup (priv->password);
  client->opaque = g_strdup (priv->opaque);
  client->salt = g_strdup (priv->salt);

  GST_INFO_OBJECT (srv,
      "Accepted client %s connection using port %d (client %p)",
      use_ssl ? "rtmps" : "rtmp", ntohs (sin.sin_port), client);

  /* ssl connection */
  if (use_ssl) {
    gchar *cert_file, *key_file, *ca_file, *ca_dir, *ciphers;
    gboolean tls1_enabled;

    g_object_get (srv,
        "cert-file", &cert_file,
        "key-file", &key_file,
        "ca-cert-file", &ca_file,
        "ca-cert-dir", &ca_dir,
        "ciphers", &ciphers, "tls1-enabled", &tls1_enabled, NULL);

    client_add_incoming_ssl (client, cert_file, key_file, ca_file, ca_dir,
        ciphers, tls1_enabled);

    g_free (cert_file);
    g_free (key_file);
    g_free (ca_file);
    g_free (ca_dir);
    g_free (ciphers);
  }

  rtmp_server_add_client_to_poll_table (srv, client);

  GST_DEBUG_OBJECT (srv, "adding client %p to fd %d", client, fd);
}

static void
_remove_poll_table_idx (PexRtmpServer * srv, size_t * poll_table_idx)
{
  PexRtmpServerPrivate *priv = srv->priv;

  if (poll_table_idx) {
    size_t idx = *poll_table_idx;
    priv->poll_table = g_array_remove_index (priv->poll_table, idx);
    idx--;
    *poll_table_idx = idx;
  }
}

static void
rtmp_server_remove_client (PexRtmpServer * srv, Client * client,
    size_t * poll_table_idx)
{
  PexRtmpServerPrivate *priv = srv->priv;

  GST_DEBUG_OBJECT (srv, "removing client %p with fd %d", client, client->fd);

  if (client->added_to_fd_table) {
    g_assert (client->fd != INVALID_FD);
    g_assert (g_hash_table_remove (priv->fd_to_client,
        GINT_TO_POINTER (client->fd)));
    tcp_disconnect (client->fd);
    client->fd = INVALID_FD;
  }

  _remove_poll_table_idx (srv, poll_table_idx);

  if (client->path)
    connections_remove_client (priv->connections, client, client->path);

  if (client->retry_connection) {
    client->handshake_state = HANDSHAKE_START;
    client->state = CLIENT_TCP_HANDSHAKE_IN_PROGRESS;
    client->retry_connection = FALSE;
    gst_atomic_queue_push (priv->dialout_clients, client);
    return;
  }

  gchar *path = g_strdup (client->path);
  gboolean publisher = client->publisher;
  client_free (client);

  if (priv->running) {
    if (publisher) {
      g_signal_emit (srv,
          pex_rtmp_server_signals[SIGNAL_ON_PUBLISH_DONE], 0, path);
    } else {
      g_signal_emit (srv,
          pex_rtmp_server_signals[SIGNAL_ON_PLAY_DONE], 0, path);
    }
  }

  if (publisher) {
    GSList *subscribers =
        connections_get_subscribers (priv->connections, path);
    for (GSList * walk = subscribers; walk; walk = g_slist_next (walk)) {
      Client *subscriber = (Client *) walk->data;
      GST_DEBUG_OBJECT (srv,
          "removing subscriber %p (fd: %d) as its publisher was removed",
          subscriber, subscriber->fd);
      subscriber->disconnect = TRUE;
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

  gboolean decreasing = (val - client->last_write_queue_size < 0);
  client->last_write_queue_size = val;

  /* Consider sending signal if queue is growing and
   * has at least 75k of data outstanding */
  if (!decreasing && client->last_write_queue_size > 75000) {
    gdouble elapsed;

    if (client->last_queue_overflow == NULL) {
      client->last_queue_overflow = g_timer_new ();
      /* Forcibly send the signal the first time the queue overflows */
      elapsed = 5.0;
    } else {
      /* Otherwise, rate-limit signals to every 2 seconds to avoid spam */
      elapsed = g_timer_elapsed (client->last_queue_overflow, NULL);
    }

    if (elapsed >= 2.0) {
      GST_DEBUG_OBJECT (srv,
          "(%s) Emitting signal on-queue-overflow due to %d bytes in queue",
          client->path, val);
      g_signal_emit (srv, pex_rtmp_server_signals[SIGNAL_ON_QUEUE_OVERFLOW],
          0, client->path);
      g_timer_start (client->last_queue_overflow);
    }
  }
}
#endif

gchar *
pex_rtmp_server_get_application_for_path (PexRtmpServer * srv, gchar * path,
    gboolean is_publisher)
{
  Client *connection = NULL;
  GST_WARNING_OBJECT (srv, "Finding application for %s - publish: %d", path,
      is_publisher);
  GList *clients = g_hash_table_get_values (srv->priv->fd_to_client);
  for (GList * walk = clients; walk; walk = g_list_next (walk)) {
    Client *client = (Client *) walk->data;
    if (g_strcmp0 (client->path, path) == 0
        && client->publisher == is_publisher) {
      connection = client;
      break;
    }
  }
  g_list_free (clients);
  if (connection != NULL) {
    return g_strdup (connection->app);
  } else {
    return NULL;
  }
}

gboolean
pex_rtmp_server_dialout (PexRtmpServer * srv,
    const gchar * src_path, const gchar * url, const gchar * addresses,
    gint src_port)
{
  return pex_rtmp_server_external_connect (srv, src_path, url, addresses, FALSE,
      src_port);
}

gboolean
pex_rtmp_server_dialin (PexRtmpServer * srv,
    const gchar * src_path, const gchar * url, const gchar * addresses,
    gint src_port)
{
  return pex_rtmp_server_external_connect (srv, src_path, url, addresses, TRUE,
      src_port);
}

static gboolean
_establish_client_tcp_connection (PexRtmpServer * srv, Client * client)
{
  PexRtmpServerPrivate *priv = srv->priv;

  if (!client_tcp_connect (client)) {
    GST_WARNING_OBJECT (srv, "Not able to connect");
    return FALSE;
  }

  if (client->use_ssl) {
    if (!client_add_outgoing_ssl (client, priv->ca_cert_file, priv->ca_cert_dir,
        priv->ciphers, priv->tls1_enabled)) {
      /* Client logs warnings for us, so no need to do that here */
      GST_WARNING_OBJECT (srv, "Outgoing SSL failed");
      return FALSE;
    }
  }
  return TRUE;
}

gboolean
pex_rtmp_server_external_connect (PexRtmpServer * srv,
    const gchar * src_path, const gchar * url, const gchar * addresses,
    const gboolean is_publisher, gint src_port)
{
  PexRtmpServerPrivate *priv = srv->priv;
  gboolean ret = FALSE;

  GST_DEBUG_OBJECT (srv, "Initiating an outgoing connection");

  Client *client = client_new (G_OBJECT (srv), priv->connections,
      priv->ignore_localhost, priv->stream_id,
      priv->chunk_size);

  if (!client_add_external_connect (client, is_publisher,
      src_path, url, addresses, src_port, priv->tcp_syncnt)) {
    GST_WARNING_OBJECT (srv, "Could not parse");
    client_free (client);
    goto done;
  }

  /* add the client to the queue, waiting to be added */
  gst_atomic_queue_push (priv->dialout_clients, client);
  ret = TRUE;

done:
  return ret;
}

static void
rtmp_server_add_pending_dialout_clients (PexRtmpServer * srv)
{
  PexRtmpServerPrivate *priv = srv->priv;

  while (gst_atomic_queue_length (priv->dialout_clients) > 0) {
    Client *client = gst_atomic_queue_pop (priv->dialout_clients);
    gboolean add = TRUE;
    if (client->fd == INVALID_FD) {
      add = _establish_client_tcp_connection (srv, client);
    }
    if (add) {
      GST_DEBUG_OBJECT (srv, "adding client %p to fd %d", client, client->fd);
      rtmp_server_add_client_to_poll_table (srv, client);
    } else {
      GST_WARNING_OBJECT (srv, "Could not establish connection to %s",
          client->url);
      client_free (client);
    }
  }
}

static void
rtmp_server_update_poll_events (PexRtmpServer * srv)
{
  PexRtmpServerPrivate *priv = srv->priv;

  for (size_t pt_idx = 0; pt_idx < priv->poll_table->len; pt_idx++) {
    struct pollfd *entry = (struct pollfd *) &g_array_index (priv->poll_table,
        struct pollfd, pt_idx);

    Client *client = g_hash_table_lookup (priv->fd_to_client,
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
}

static gboolean
rtmp_server_do_poll (PexRtmpServer * srv)
{
  PexRtmpServerPrivate *priv = srv->priv;

  rtmp_server_add_pending_dialout_clients (srv);

  rtmp_server_update_poll_events (srv);

  /* waiting for traffic on all connections */
  priv->poll_count++;
  const gint timeout = 200;     /* 200 ms second */
  gint result = poll ((struct pollfd *) &priv->poll_table->data[0],
      priv->poll_table->len, timeout);

  if (priv->running == FALSE)
    return FALSE;

  if (result < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    GST_WARNING_OBJECT (srv, "poll() failed: %s", strerror (errno));
    return FALSE;
  }

  for (size_t pt_idx = 0; pt_idx < priv->poll_table->len; pt_idx++) {
    if (priv->running == FALSE)
      return FALSE;

    struct pollfd *entry = (struct pollfd *) &g_array_index (priv->poll_table,
        struct pollfd, pt_idx);
    Client *client = g_hash_table_lookup (priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));

    /* asked to disconnect */
    if (client && client->disconnect) {
      GST_INFO_OBJECT (srv, "Disconnecting client for path=%s on request",
          client->path);
      rtmp_server_remove_client (srv, client, &pt_idx);
      continue;
    }

    /* fd closed */
    if (client && entry->revents & POLLNVAL) {
      GST_WARNING_OBJECT (srv,
          "poll() called on closed fd - removing client (path=%s, publisher=%d)",
          client->path, client->publisher);
      rtmp_server_remove_client (srv, client, &pt_idx);
      continue;
    }

    /* ready to send */
    if (client && entry->revents & POLLOUT) {
      gboolean ret = client_try_to_send (client);
      if (!ret) {
        GST_WARNING_OBJECT (srv,
            "client error, send failed (path=%s, publisher=%d)", client->path,
            client->publisher);
        rtmp_server_remove_client (srv, client, &pt_idx);
        continue;
      }
    }

    /* data to receive */
    if (entry->revents & POLLIN) {
      /* new connection, create a client */
      if (client == NULL) {
        rtmp_server_create_client (srv, entry->fd);
        continue;
      }

      gboolean ret = client_receive (client);
      if (!ret) {
        GST_WARNING_OBJECT (srv,
            "client error: client_recv_from_client failed (client=%p path=%s, publisher=%d)",
            client, client->path, client->publisher);
        rtmp_server_remove_client (srv, client, &pt_idx);
      }
    }
  }

  return TRUE;
}

static gpointer
rtmp_server_func (gpointer data)
{
  PexRtmpServer *srv = PEX_RTMP_SERVER_CAST (data);
  PexRtmpServerPrivate *priv = srv->priv;

  gboolean ret = TRUE;
  signal (SIGPIPE, SIG_IGN);

  while (priv->running && ret) {
    ret = rtmp_server_do_poll (srv);
  }

  /* remove outstanding clients */
  for (size_t pt_idx = 0; pt_idx < priv->poll_table->len; pt_idx++) {
    struct pollfd *entry = (struct pollfd *) &g_array_index (priv->poll_table,
        struct pollfd, pt_idx);
    Client *client = g_hash_table_lookup (priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));
    if (client)
      rtmp_server_remove_client (srv, client, &pt_idx);
    else
      _remove_poll_table_idx (srv, &pt_idx);
  }

  while (gst_atomic_queue_length (priv->dialout_clients) > 0) {
    Client *client = gst_atomic_queue_pop (priv->dialout_clients);
    rtmp_server_remove_client (srv, client, NULL);
  }

  return NULL;
}

gint
pex_rtmp_server_add_listen_fd (PexRtmpServer * srv, gint port)
{
  gint fd = socket (AF_INET6, SOCK_STREAM, 0);
  g_assert_cmpint (fd, >=, 0);

  int sock_optval = 1;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &sock_optval, sizeof (sock_optval));

  struct sockaddr_in6 sin;
  memset (&sin, 0, sizeof (struct sockaddr_in6));
  sin.sin6_family = AF_INET6;
  sin.sin6_port = htons (port);
  sin.sin6_addr = in6addr_any;

  if (bind (fd, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
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
  PexRtmpServerPrivate *priv = srv->priv;

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
  PexRtmpServerPrivate *priv = srv->priv;

  GST_DEBUG_OBJECT (srv, "Stopping...");
  priv->running = FALSE;
  if (priv->thread)
    g_thread_join (priv->thread);

  if (priv->listen_fd > 0)
    close (priv->listen_fd);
  if (priv->listen_ssl_fd > 0)
    close (priv->listen_ssl_fd);
}

void
pex_rtmp_server_free (PexRtmpServer * srv)
{
  g_object_unref (srv);
}
