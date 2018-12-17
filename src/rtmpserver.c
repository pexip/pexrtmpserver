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

#ifdef HAVE_LINUX_SOCKIOS_H
#include <linux/sockios.h>
#include <sys/ioctl.h>
#endif

GST_DEBUG_CATEGORY (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

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

struct _PexRtmpServer
{
  GObject parent_instance;

  GstPoll *fd_set;
  GList *active_clients;

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
  GstPollFD listen_gfd;
  GstPollFD listen_ssl_gfd;

  gboolean running;
  GThread *thread;

  Connections *connections;
  GstAtomicQueue *dialout_clients;

  GHashTable *direct_publishers;
};

G_DEFINE_TYPE (PexRtmpServer, pex_rtmp_server, G_TYPE_OBJECT)

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
  srv->application_name = NULL;
  srv->port = DEFAULT_PORT;
  srv->ssl_port = DEFAULT_SSL_PORT;
  srv->cert_file = NULL;
  srv->key_file = NULL;
  srv->ca_cert_file = NULL;
  srv->ca_cert_dir = NULL;
  srv->ciphers = NULL;
  srv->tls1_enabled = DEFAULT_TLS1_ENABLED;
  srv->ignore_localhost = DEFAULT_IGNORE_LOCALHOST;

  srv->thread = NULL;

  srv->fd_set = gst_poll_new (TRUE);

  srv->connections = connections_new ();
  srv->dialout_clients = gst_atomic_queue_new (0);

  /* FIXME: only need to generate this when username and password is set */
  guint32 rand_data = g_random_int();
  srv->opaque = g_base64_encode ((guchar *)&rand_data, sizeof (guint32));
  rand_data = g_random_int();
  srv->salt = g_base64_encode ((guchar *)&rand_data, sizeof (guint32));

  srv->direct_publishers = g_hash_table_new_full (
      g_str_hash, g_str_equal, g_free, NULL);
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

  g_free (srv->application_name);
  g_free (srv->cert_file);
  g_free (srv->key_file);
  g_free (srv->ca_cert_file);
  g_free (srv->ca_cert_dir);
  g_free (srv->ciphers);
  g_free (srv->opaque);
  g_free (srv->salt);
  g_free (srv->username);
  g_free (srv->password);


  gst_poll_free (srv->fd_set);
  g_list_free (srv->active_clients);


  connections_free (srv->connections);
  gst_atomic_queue_unref (srv->dialout_clients);
  g_hash_table_destroy (srv->direct_publishers);

  G_OBJECT_CLASS (pex_rtmp_server_parent_class)->finalize (obj);
}

static void
pex_rtmp_server_set_property (GObject * obj, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  PexRtmpServer *srv = PEX_RTMP_SERVER_CAST (obj);

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      srv->application_name = g_value_dup_string (value);
      break;
    case PROP_PORT:
      srv->port = g_value_get_int (value);
      break;
    case PROP_SSL_PORT:
      srv->ssl_port = g_value_get_int (value);
      break;
    case PROP_CERT_FILE:
      srv->cert_file = g_value_dup_string (value);
      break;
    case PROP_KEY_FILE:
      srv->key_file = g_value_dup_string (value);
      break;
    case PROP_CA_CERT_FILE:
      srv->ca_cert_file = g_value_dup_string (value);
      break;
    case PROP_CA_CERT_DIR:
      srv->ca_cert_dir = g_value_dup_string (value);
      break;
    case PROP_CIPHERS:
      srv->ciphers = g_value_dup_string (value);
      break;
    case PROP_TLS1_ENABLED:
      srv->tls1_enabled = g_value_get_boolean (value);
      break;
    case PROP_IGNORE_LOCALHOST:
      srv->ignore_localhost = g_value_get_boolean (value);
      break;
    case PROP_STREAM_ID:
      srv->stream_id = g_value_get_int (value);
      break;
    case PROP_CHUNK_SIZE:
      srv->chunk_size = g_value_get_int (value);
      break;
    case PROP_TCP_SYNCNT:
      srv->tcp_syncnt = g_value_get_int (value);
      break;
    case PROP_USERNAME:
      g_free (srv->username);
      srv->username = g_value_dup_string (value);
      break;
    case PROP_PASSWORD:
      g_free (srv->password);
      srv->password = g_value_dup_string (value);
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

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      g_value_set_string (value, srv->application_name);
      break;
    case PROP_PORT:
      g_value_set_int (value, srv->port);
      break;
    case PROP_SSL_PORT:
      g_value_set_int (value, srv->ssl_port);
      break;
    case PROP_CERT_FILE:
      g_value_set_string (value, srv->cert_file);
      break;
    case PROP_KEY_FILE:
      g_value_set_string (value, srv->key_file);
      break;
    case PROP_CA_CERT_FILE:
      g_value_set_string (value, srv->ca_cert_file);
      break;
    case PROP_CA_CERT_DIR:
      g_value_set_string (value, srv->ca_cert_dir);
      break;
    case PROP_CIPHERS:
      g_value_set_string (value, srv->ciphers);
      break;
    case PROP_TLS1_ENABLED:
      g_value_set_boolean (value, srv->tls1_enabled);
      break;
    case PROP_IGNORE_LOCALHOST:
      g_value_set_boolean (value, srv->ignore_localhost);
      break;
    case PROP_STREAM_ID:
      g_value_set_int (value, srv->stream_id);
      break;
    case PROP_CHUNK_SIZE:
      g_value_set_int (value, srv->chunk_size);
      break;
    case PROP_TCP_SYNCNT:
      g_value_set_int (value, srv->tcp_syncnt);
      break;
    case PROP_POLL_COUNT:
      g_value_set_int (value, srv->poll_count);
      break;
    case PROP_USERNAME:
      g_value_set_string (value, srv->username);
      break;
    case PROP_PASSWORD:
      g_value_set_string (value, srv->password);
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

  GST_DEBUG_CATEGORY_INIT (pex_rtmp_server_debug, "pexrtmpserver", 0,
      "pexrtmpserver");
}

static void
rtmp_server_add_client_to_poll_table (PexRtmpServer * srv, Client * client)
{
  GST_DEBUG_OBJECT (srv, "Appending client %p to poll-list", client);

  gst_poll_fd_init (&client->gfd);
  client->gfd.fd = client->fd;
  gst_poll_add_fd (srv->fd_set, &client->gfd);
  gst_poll_fd_ctl_read (srv->fd_set, &client->gfd, TRUE);
  srv->active_clients = g_list_append (srv->active_clients, client);
  client->added_to_fd_table = TRUE;
}

static void
rtmp_server_create_client (PexRtmpServer * srv, gint listen_fd)
{
  gint fd = tcp_accept (listen_fd);
  if (fd < 0) {
    GST_WARNING_OBJECT (srv, "Unable to accept a client on fd %d: %s",
        listen_fd, strerror (errno));
    return;
  }

  /* make the connection non-blocking */
  tcp_set_nonblock (fd, TRUE);

  gboolean use_ssl = listen_fd == srv->listen_ssl_fd;
  Client *client = client_new (G_OBJECT (srv), srv->connections,
      srv->ignore_localhost, srv->stream_id,
      srv->chunk_size);

  /* FIXME: pass with functions instead */
  client->fd = fd;
  client->use_ssl = use_ssl;
  client->username = g_strdup (srv->username);
  client->password = g_strdup (srv->password);
  client->opaque = g_strdup (srv->opaque);
  client->salt = g_strdup (srv->salt);

  GST_INFO_OBJECT (srv, "Accepted %s connection with client %p",
      use_ssl ? "rtmps" : "rtmp", client);

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

#ifdef HAVE_LINUX_SOCKIOS_H
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
  gchar *app = NULL;

  GST_INFO_OBJECT (srv, "Finding application for %s - publish: %d", path,
      is_publisher);
  for (GList * walk = srv->active_clients; walk; walk = g_list_next (walk)) {
    Client *client = walk->data;
    if (g_strcmp0 (client->path, path) == 0
        && client->publisher == is_publisher) {
      app = g_strdup (client->app);
      break;
    }
  }

  return app;
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
  if (!client_tcp_connect (client)) {
    GST_WARNING_OBJECT (srv, "Not able to connect");
    return FALSE;
  }

  if (client->use_ssl) {
    if (!client_add_outgoing_ssl (client, srv->ca_cert_file, srv->ca_cert_dir,
        srv->ciphers, srv->tls1_enabled)) {
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
  gboolean ret = FALSE;

  GST_DEBUG_OBJECT (srv, "Initiating an outgoing connection");

  Client *client = client_new (G_OBJECT (srv), srv->connections,
      srv->ignore_localhost, srv->stream_id,
      srv->chunk_size);

  if (!client_add_external_connect (client, is_publisher,
      src_path, url, addresses, src_port, srv->tcp_syncnt)) {
    GST_WARNING_OBJECT (srv, "Could not parse");
    client_free (client);
    goto done;
  }

  /* add the client to the queue, waiting to be added */
  gst_atomic_queue_push (srv->dialout_clients, client);
  ret = TRUE;

done:
  return ret;
}

static void
rtmp_server_remove_client (PexRtmpServer * srv, Client * client)
{
  GST_DEBUG_OBJECT (srv, "removing client %p with fd %d", client, client->fd);

  if (client->added_to_fd_table) {
    gst_poll_remove_fd (srv->fd_set, &client->gfd);
    srv->active_clients = g_list_remove (srv->active_clients, client);

    g_assert (client->fd != INVALID_FD);
    tcp_disconnect (client->fd);
    client->fd = INVALID_FD;
  }

  if (client->path)
    connections_remove_client (srv->connections, client, client->path);

  if (client->retry_connection) {
    GST_INFO_OBJECT (srv, "Retrying the connection for client %p", client);
    client->handshake_state = HANDSHAKE_START;
    client->state = CLIENT_TCP_HANDSHAKE_IN_PROGRESS;
    client->retry_connection = FALSE;
    gst_atomic_queue_push (srv->dialout_clients, client);
    return;
  }

  gchar *path = g_strdup (client->path);
  gboolean publisher = client->publisher;
  client_free (client);

  if (srv->running) {
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
        connections_get_subscribers (srv->connections, path);
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

static void
rtmp_server_add_pending_dialout_clients (PexRtmpServer * srv)
{
  while (gst_atomic_queue_length (srv->dialout_clients) > 0) {
    Client *client = gst_atomic_queue_pop (srv->dialout_clients);
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
rtmp_server_update_poll_ctl (PexRtmpServer * srv)
{
  for (GList *walk = srv->active_clients; walk; walk = walk->next) {
    Client *client = walk->data;
#ifdef HAVE_LINUX_SOCKIOS_H
    if (!client->publisher)
      rtmp_server_update_send_queues (srv, client);
#endif
    gboolean read, write;
    client_get_poll_ctl (client, &read, &write);
    gst_poll_fd_ctl_read (srv->fd_set, &client->gfd, read);
    gst_poll_fd_ctl_write (srv->fd_set, &client->gfd, write);
  }
}

gboolean
rtmp_server_do_poll (PexRtmpServer * srv)
{
  rtmp_server_add_pending_dialout_clients (srv);

  rtmp_server_update_poll_ctl (srv);

  /* waiting for traffic on all connections */
  srv->poll_count++;
  gint result = gst_poll_wait (srv->fd_set, 200 * GST_MSECOND);

  if (srv->running == FALSE)
    return FALSE;

  if (result < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    GST_WARNING_OBJECT (srv, "poll() failed: %s", strerror (errno));
    return FALSE;
  }

  /* check for new connections */
  if (gst_poll_fd_can_read (srv->fd_set, &srv->listen_gfd)) {
    rtmp_server_create_client (srv, srv->listen_gfd.fd);
    return TRUE;
  }
  if (gst_poll_fd_can_read (srv->fd_set, &srv->listen_ssl_gfd)) {
    rtmp_server_create_client (srv, srv->listen_ssl_gfd.fd);
    return TRUE;
  }

  for (GList *walk = srv->active_clients; walk; walk = walk->next) {
    Client *client = walk->data;

    /* asked to disconnect */
    if (client->disconnect) {
      GST_INFO_OBJECT (srv, "Disconnecting client for path=%s on request",
          client->path);
      rtmp_server_remove_client (srv, client);
      break;
    }

    /* ready to send */
    if (gst_poll_fd_can_write (srv->fd_set, &client->gfd)) {
      gboolean ret = client_try_to_send (client);
      if (!ret) {
        GST_WARNING_OBJECT (srv,
            "client error, send failed (path=%s, publisher=%d)", client->path,
            client->publisher);
        rtmp_server_remove_client (srv, client);
        break;
      }
    }

    /* data to receive */
    if (gst_poll_fd_can_read (srv->fd_set, &client->gfd)) {
      gboolean ret = client_receive (client);
      if (!ret) {
        GST_WARNING_OBJECT (srv,
            "client error: client_recv_from_client failed (client=%p path=%s, publisher=%d)",
            client, client->path, client->publisher);
        rtmp_server_remove_client (srv, client);
        break;
      }
    }

    /* fd closed */
    if (gst_poll_fd_has_closed (srv->fd_set, &client->gfd) ||
        gst_poll_fd_has_error (srv->fd_set, &client->gfd)) {
      GST_WARNING_OBJECT (srv,
          "poll() called on closed fd - removing client (path=%s, publisher=%d)",
          client->path, client->publisher);
      rtmp_server_remove_client (srv, client);
      break;
    }
  }

  return TRUE;
}

static gpointer
rtmp_server_func (gpointer data)
{
  PexRtmpServer *srv = PEX_RTMP_SERVER_CAST (data);

  gboolean ret = TRUE;
#ifndef _MSC_VER
  signal (SIGPIPE, SIG_IGN);
#endif

  while (srv->running && ret) {
    ret = rtmp_server_do_poll (srv);
  }

  while (srv->active_clients) {
    Client *client = srv->active_clients->data;
    rtmp_server_remove_client (srv, client);
  }

  while (gst_atomic_queue_length (srv->dialout_clients) > 0) {
    Client *client = gst_atomic_queue_pop (srv->dialout_clients);
    rtmp_server_remove_client (srv, client);
  }

  return NULL;
}

gboolean
pex_rtmp_server_start (PexRtmpServer * srv)
{
  /* listen for normal and ssl connections */
  srv->listen_fd = tcp_listen (srv->port);
  if (srv->listen_fd <= 0)
    return FALSE;
  srv->listen_ssl_fd = tcp_listen (srv->ssl_port);
  if (srv->listen_ssl_fd <= 0)
    return FALSE;

  /* add fds to poll table */
  gst_poll_fd_init (&srv->listen_gfd);
  gst_poll_fd_init (&srv->listen_ssl_gfd);
  srv->listen_gfd.fd = srv->listen_fd;
  srv->listen_ssl_gfd.fd = srv->listen_ssl_fd;
  gst_poll_add_fd (srv->fd_set, &srv->listen_gfd);
  gst_poll_add_fd (srv->fd_set, &srv->listen_ssl_gfd);

  gst_poll_fd_ctl_read (srv->fd_set, &srv->listen_gfd, TRUE);
  gst_poll_fd_ctl_read (srv->fd_set, &srv->listen_ssl_gfd, TRUE);

  srv->running = TRUE;
  srv->thread = g_thread_new ("RTMPServer", rtmp_server_func, srv);

  return TRUE;
}

void
pex_rtmp_server_stop (PexRtmpServer * srv)
{
  GST_DEBUG_OBJECT (srv, "Stopping...");
  srv->running = FALSE;
  if (srv->thread)
    g_thread_join (srv->thread);

  if (srv->listen_fd > 0)
    tcp_disconnect (srv->listen_fd);
  if (srv->listen_ssl_fd > 0)
    tcp_disconnect (srv->listen_ssl_fd);
}

void
pex_rtmp_server_free (PexRtmpServer * srv)
{
  g_object_unref (srv);
}
