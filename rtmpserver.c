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
#include "handshake.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

// GOBJECT Stuff
GST_DEBUG_CATEGORY (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug
G_DEFINE_TYPE (PexRtmpServer, pex_rtmp_server, G_TYPE_OBJECT)
#define debug(fmt...) GST_INFO(fmt)
#define warning(fmt...) GST_WARNING(fmt)

#define PEX_RTMP_SERVER_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj),\
      PEX_TYPE_RTMP_SERVER, PexRtmpServerPrivate))

#define DEFAULT_APPLICATION_NAME ""
#define DEFAULT_PORT 1935
#define DEFAULT_SSL_PORT 443
#define DEFAULT_CERT ""
#define DEFAULT_KEY ""

enum
{
  PROP_0,
  PROP_APPLICATION_NAME,
  PROP_PORT,
  PROP_SSL_PORT,
  PROP_CERT,
  PROP_KEY,
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
  gchar * cert;
  gchar * key;

  gint listen_fd;
  gint listen_ssl_fd;
  GHashTable * publishers;
  GHashTable * subscriber_lists;
  GArray * poll_table;
  GHashTable * fd_to_client;
  gboolean running;
  GThread * thread;
  GTimer * last_queue_overflow;

  Connections * connections;
  PexRtmpHandshake * handshake;
};


PexRtmpServer *
pex_rtmp_server_new (const gchar * application_name, gint port, gint ssl_port,
    const gchar * cert, const gchar * key)
{
  return g_object_new (PEX_TYPE_RTMP_SERVER,
      "application-name", application_name,
      "port", port,
      "ssl-port", ssl_port,
      "cert", cert,
      "key", key,
      NULL);
}

void __attribute__ ((unused))
pex_rtmp_server_connect_signal (PexRtmpServer * self,
    gchar * signal_name, gboolean (*callback)(gchar * path))
{
  g_signal_connect(self, signal_name, G_CALLBACK (callback), NULL);
}

static void
pex_rtmp_server_init (PexRtmpServer *self)
{
  self->priv = PEX_RTMP_SERVER_GET_PRIVATE (self);
  self->priv->application_name = NULL;
  self->priv->port = DEFAULT_PORT;
  self->priv->ssl_port = DEFAULT_SSL_PORT;
  self->priv->cert = NULL;
  self->priv->key = NULL;

  self->priv->thread = NULL;
  self->priv->handshake = pex_rtmp_handshake_new ();
  self->priv->last_queue_overflow = NULL;
}

static void
pex_rtmp_server_dispose (GObject * obj)
{
  G_OBJECT_CLASS (pex_rtmp_server_parent_class)->dispose (obj);
}

static void
pex_rtmp_server_finalize (GObject * obj)
{
  PexRtmpServer * self = PEX_RTMP_SERVER_CAST (obj);

  g_free (self->priv->application_name);
  g_free (self->priv->cert);
  g_free (self->priv->key);
  pex_rtmp_handshake_free (self->priv->handshake);

  G_OBJECT_CLASS (pex_rtmp_server_parent_class)->finalize (obj);
}

static void
pex_rtmp_server_set_property (GObject * obj, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  PexRtmpServer * self = PEX_RTMP_SERVER_CAST (obj);

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      self->priv->application_name = g_value_dup_string (value);
      break;
    case PROP_PORT:
      self->priv->port = g_value_get_int (value);
      break;
    case PROP_SSL_PORT:
      self->priv->ssl_port = g_value_get_int (value);
      break;
    case PROP_CERT:
      self->priv->cert = g_value_dup_string (value);
      break;
    case PROP_KEY:
      self->priv->key = g_value_dup_string (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop_id, pspec);
  }
}

static void
pex_rtmp_server_get_property (GObject * obj, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  PexRtmpServer * self = PEX_RTMP_SERVER_CAST (obj);

  switch (prop_id) {
    case PROP_APPLICATION_NAME:
      g_value_set_string (value, self->priv->application_name);
      break;
    case PROP_PORT:
      g_value_set_int (value, self->priv->port);
      break;
    case PROP_SSL_PORT:
      g_value_set_int (value, self->priv->ssl_port);
      break;
    case PROP_CERT:
      g_value_set_string (value, self->priv->cert);
      break;
    case PROP_KEY:
      g_value_set_string (value, self->priv->key);
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

  g_object_class_install_property (gobject_class, PROP_CERT,
      g_param_spec_string ("cert", "Certificate (PEM)",
          "The ssl certificate", DEFAULT_CERT,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (gobject_class, PROP_KEY,
      g_param_spec_string ("key", "Key (PEM)",
          "The ssl key", DEFAULT_KEY,
          G_PARAM_CONSTRUCT_ONLY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

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

gboolean
rtmp_server_handshake_client (Client * client)
{
  Handshake serversig;
  Handshake clientsig;
  guint8 c;

  if (client_recv_all (client, &c, 1) < 1)
    return FALSE;
  if (c != HANDSHAKE_PLAINTEXT) {
    g_warning ("only plaintext handshake supported");
    return FALSE;
  }

  if (client_send_all (client, &c, 1) < 1)
    return FALSE;

  memset (&serversig, 0, sizeof serversig);
  serversig.flags[0] = 0x03;
  for (int i = 0; i < RANDOM_LEN; ++i) {
    serversig.random[i] = rand ();
  }

  if (client_send_all (client, &serversig, sizeof serversig) < sizeof serversig)
    return FALSE;

  /* Echo client's signature back */
  if (client_recv_all (client, &clientsig, sizeof serversig) < sizeof serversig)
    return FALSE;

  if (client_send_all (client, &clientsig, sizeof serversig) < sizeof serversig)
    return FALSE;

  if (client_recv_all (client, &clientsig, sizeof serversig) < sizeof serversig)
    return FALSE;
  if (memcmp (serversig.random, clientsig.random, RANDOM_LEN) != 0) {
    debug ("invalid handshake");
    return FALSE;
  }

  //client->read_seq = 1 + sizeof serversig * 2;
  //client->written_seq = 1 + sizeof serversig * 2;

  return TRUE;
}

gboolean
rtmp_server_flash_handshake (PexRtmpServer * srv, Client * client)
{
  guint8 incoming_0[HANDSHAKE_LENGTH + 1];
  guint8 incoming_1[HANDSHAKE_LENGTH];
  guint8 * outgoing;
  guint outgoing_length;
  
  /* receive the handshake from the client */
  if (client_recv_all (client, &incoming_0, sizeof (incoming_0)) < sizeof (incoming_0))
    return FALSE;

  if (!pex_rtmp_handshake_process (srv->priv->handshake,
      incoming_0, sizeof (incoming_0))) {
    return FALSE;
  }

  /* send a reply */
  outgoing = pex_rtmp_handshake_get_buffer (srv->priv->handshake);
  outgoing_length = pex_rtmp_handshake_get_length (srv->priv->handshake);
  if (client_send_all (client, outgoing, outgoing_length) < outgoing_length)
    return FALSE;

  /* receive another handshake */
  if (client_recv_all (client, &incoming_1, sizeof (incoming_1)) < sizeof (incoming_1))
    return FALSE;

  return pex_rtmp_handshake_verify_reply (srv->priv->handshake, incoming_1);
}

static void
pex_rtmp_add_fd_to_poll_table (PexRtmpServer * srv, gint fd)
{
  struct pollfd entry;
  entry.events = POLLIN;
  entry.revents = 0;
  entry.fd = fd;
  srv->priv->poll_table = g_array_append_val (srv->priv->poll_table, entry);

  debug ("Added fd %d to poll-table", fd);
}

static void
rtmp_server_create_client (PexRtmpServer * srv, gint listen_fd)
{
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof (sin);
  gint fd = accept (listen_fd, (struct sockaddr *)&sin, &addrlen);
  if (fd < 0) {
    warning ("Unable to accept a client on fd %d: %s", listen_fd, strerror (errno));
    return;
  }

  gboolean use_ssl = listen_fd == srv->priv->listen_ssl_fd;
  debug ("We got an %s connection", use_ssl ? "rtmps" : "rtmp");
  Client * client = client_new (fd, srv->priv->connections, G_OBJECT (srv), use_ssl);

  /* handshake */
  if (!rtmp_server_flash_handshake (srv, client)) {
    warning ("Handshake Failed");
    client_free (client);
    return;
  }

  /* make the connection non-blocking */
  set_nonblock (fd, TRUE);

  /* create a poll entry, and link it to the client */
  pex_rtmp_add_fd_to_poll_table (srv, fd);
  g_hash_table_insert (srv->priv->fd_to_client, GINT_TO_POINTER (fd), client);

  debug ("adding client %p to fd %d", client, fd);
}

static void
rtmp_server_remove_client (PexRtmpServer * srv, Client * client)
{
  debug ("removing client %p with fd %d", client, client->fd);
  g_hash_table_remove (srv->priv->fd_to_client, GINT_TO_POINTER (client->fd));
  close (client->fd);

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
  g_free (path);
}

static void
rtmp_server_update_send_queues (PexRtmpServer * srv, Client * client)
{
  int val, error;

  error = ioctl (client->fd, SIOCOUTQ, &val);
  if (error)
    val = 0;

  gboolean decreasing = (val - client->write_queue_size < 0);
  client->write_queue_size = val;
  if (!decreasing && client->write_queue_size > 30000) {
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


gboolean
pex_rtmp_server_parse_url (PexRtmpServer * self, const gchar * url,
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
    GST_WARNING_OBJECT (self, "Unable to parse");
    ret = FALSE;
    goto done;
  }

  /* then clip before and after protocol (rtmp://) */
  protocol_clip = g_strsplit (url_nospace, "://", 1024);
  const gchar * protocol_tmp = protocol_clip[0];
  const gchar * the_rest = protocol_clip[1];
  if (!(protocol_tmp && the_rest && (g_strcmp0 (protocol_tmp, "rtmp") == 0 || g_strcmp0 (protocol_tmp, "rtmps") == 0))) {
    GST_WARNING_OBJECT (self, "Unable to parse");
    ret = FALSE;
    goto done;
  }

  /* clip all "/" bits */
  slash_clip = g_strsplit (the_rest, "/", 1024);
  gint idx = 0;
  while (slash_clip[idx] != NULL)
    idx++;
  if (idx < 3) {
    GST_WARNING_OBJECT (self, "Not able to find address, application_name and path");
    ret = FALSE;
    goto done;
  }

  /* clip IP and port */
  const gchar * address = slash_clip[0];
  address_clip = g_strsplit (address, ":", 1024);
  const gchar * port_str = address_clip[1];
  if (port_str && strlen (port_str) > 0) {
    *port = atoi (port_str);
  } else {
    GST_WARNING_OBJECT (self, "Specify the port, buster!");
    ret = FALSE;
    goto done;
  }

  *protocol = g_strdup (protocol_tmp);
  *path = g_strdup (slash_clip[idx - 1]); /* path is last */
  *application_name = g_strndup (&the_rest[strlen (address) + 1],
      strlen (the_rest) - strlen (address) - strlen (*path) - 2);
  *ip = g_strdup (address_clip[0]);

  GST_DEBUG_OBJECT (self, "Parsed: Protocol: %s, Ip: %s, Port: %d, Application Name: %s, Path: %s",
      *protocol, *ip, *port, *application_name, *path);

done:
  g_strfreev (space_clip);
  g_strfreev (protocol_clip);
  g_strfreev (slash_clip);
  g_strfreev (address_clip);

  return ret;
}

void
pex_rtmp_server_dialout (PexRtmpServer * self,
    const gchar * src_path, const gchar * url)
{
  (void)src_path;

  struct sockaddr_in service;

  memset(&service, 0, sizeof (struct sockaddr_in));
  service.sin_family = AF_INET;

  gchar * protocol = NULL;
  gint port;
  gchar * ip = NULL;
  gchar * application_name = NULL;
  gchar * dest_path = NULL;

  if (!pex_rtmp_server_parse_url (self, url,
      &protocol, &port, &ip, &application_name, &dest_path)) {
    return;
  }

  g_free (protocol);
  g_free (ip);
  g_free (application_name);
  g_free (dest_path);

}

static gboolean
rtmp_server_do_poll (PexRtmpServer * srv)
{
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  for (size_t i = 0; i < priv->poll_table->len; ++i) {
    struct pollfd * entry = (struct pollfd *)&g_array_index (
        priv->poll_table, struct pollfd, i);

    Client * client = g_hash_table_lookup (priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));
    if (client != NULL) {
      if (!client->publisher) {
        rtmp_server_update_send_queues (srv, client);
      }

      if (client->send_queue->len > 0) {
        entry->events = POLLIN | POLLOUT;
      } else {
        entry->events = POLLIN;
      }
    }
  }

  /* waiting for traffic on all connections */
  const gint timeout = 200; /* 200 ms second */
  if (poll ((struct pollfd *)&priv->poll_table->data[0],
      priv->poll_table->len, timeout) < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    g_warning ("poll() failed: %s", strerror (errno));
    return FALSE;
  }

  if (priv->running == FALSE)
    return FALSE;

  for (size_t i = 0; i < priv->poll_table->len; ++i) {
    if (priv->running == FALSE)
      return FALSE;

    struct pollfd * entry = (struct pollfd *)&g_array_index (
        priv->poll_table, struct pollfd, i);
    Client * client = g_hash_table_lookup (priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));
    debug ("fd %d has client %p", entry->fd, client);

    /* ready to send */
    if (client && entry->revents & POLLOUT) {
      if (!client_try_to_send (client)) {
        warning ("client error, send failed");
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
        warning ("client error: client_recv_from_client failed");
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
  PexRtmpServer * srv = PEX_RTMP_SERVER_CAST(data);
  gboolean ret = TRUE;
  signal (SIGPIPE, SIG_IGN);

  while (srv->priv->running && ret) {
    ret = rtmp_server_do_poll (srv);
  }

  /* remove outstanding clients */
  for (size_t i = 0; i < srv->priv->poll_table->len; ++i) {
    struct pollfd * entry = (struct pollfd *)&g_array_index (
        srv->priv->poll_table, struct pollfd, i);
    Client * client = g_hash_table_lookup (srv->priv->fd_to_client,
        GINT_TO_POINTER (entry->fd));
    if (client)
      rtmp_server_remove_client (srv, client);
    srv->priv->poll_table = g_array_remove_index (srv->priv->poll_table, i);
    i--;
  }

  return NULL;
}

static gint
add_listen_fd (gint port)
{
  gint fd = socket (AF_INET, SOCK_STREAM, 0);
  int sock_optval = 1;
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR,
      &sock_optval, sizeof (sock_optval));

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  sin.sin_addr.s_addr = INADDR_ANY;
  g_assert_cmpint (fd, >=, 0);

  if (bind (fd, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
    g_warning ("Unable to listen: %s", strerror (errno));
    return -1;
  }

  listen (fd, 10);
  debug ("Listening on port %d with fd %d", port, fd);

  return fd;
}


gboolean
pex_rtmp_server_start (PexRtmpServer * srv)
{
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  priv->poll_table = g_array_new (FALSE, TRUE, sizeof (struct pollfd));
  priv->fd_to_client = g_hash_table_new (NULL, NULL);
  priv->connections = connections_new ();

  /* listen for normal and ssl connections */
  priv->listen_fd = add_listen_fd (priv->port);
  if (priv->listen_fd <= 0)
    return FALSE;
  priv->listen_ssl_fd = add_listen_fd (priv->ssl_port);
  if (priv->listen_ssl_fd <= 0)
    return FALSE;

  /* add fds to poll table */
  pex_rtmp_add_fd_to_poll_table (srv, priv->listen_fd);
  pex_rtmp_add_fd_to_poll_table (srv, priv->listen_ssl_fd);

  priv->running = TRUE;
  priv->thread = g_thread_new ("RTMPServer", rtmp_server_func, srv);
  return TRUE;
}

void
pex_rtmp_server_stop (PexRtmpServer * srv)
{
  PexRtmpServerPrivate * priv = PEX_RTMP_SERVER_GET_PRIVATE (srv);

  debug ("Stopping...");
  priv->running = FALSE;
  g_thread_join (priv->thread);
  if (priv->last_queue_overflow != NULL) {
    g_timer_destroy (priv->last_queue_overflow);
  }
  close (priv->listen_fd);
  close (priv->listen_ssl_fd);

  g_array_free (priv->poll_table, TRUE);
  priv->poll_table = NULL;
  g_hash_table_destroy (priv->fd_to_client);
  connections_free (priv->connections);
  priv->connections = NULL;
}

void pex_rtmp_server_free (PexRtmpServer * srv)
{
  g_object_unref (srv);
}
