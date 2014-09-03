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
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <unistd.h>
#include <fcntl.h>

// GOBJECT Stuff

G_DEFINE_TYPE (PexRtmpServer, pex_rtmp_server, G_TYPE_OBJECT)

#define DEFAULT_APPLICATION_NAME ""
#define DEFAULT_PORT 1935
#define PEX_RTMP_SERVER_GET_PRIVATE(obj) (G_TYPE_INSTANCE_GET_PRIVATE ((obj),\
      PEX_TYPE_RTMP_SERVER, PexRtmpServerPrivate))

enum
{
  PROP_0,
  PROP_APPLICATION_NAME,
  PROP_PORT,
};

enum
{
  SIGNAL_ON_PLAY,
  SIGNAL_ON_PLAY_DONE,
  SIGNAL_ON_PUBLISH,
  SIGNAL_ON_PUBLISH_DONE,
  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


struct _PexRtmpServerPrivate
{
  gchar * application_name;
  gint port;

  gint listen_fd;
  GHashTable * publishers;
  GHashTable * subscriber_lists;
  GArray * poll_table;
  GSList * clients;
  gboolean running;
  GThread * thread;

  Connections * connections;
};


PexRtmpServer *
pex_rtmp_server_new(const gchar * application_name, gint port)
{
  return g_object_new(PEX_TYPE_RTMP_SERVER,
                      "application-name", application_name,
                      "port", port,
                      NULL);
}

void __attribute__ ((unused))
pex_rtmp_server_connect_signal(PexRtmpServer * self, gchar * signal_name, gboolean (*callback)(gchar * path))
{
  g_signal_connect(self, signal_name, G_CALLBACK(callback), NULL);
}

static void
pex_rtmp_server_init (PexRtmpServer *self)
{
  int sock_optval = 1;
  self->priv = PEX_RTMP_SERVER_GET_PRIVATE (self);
  self->priv->application_name = NULL;
  self->priv->port = DEFAULT_PORT;
  self->priv->poll_table = g_array_new (FALSE, TRUE, sizeof (struct pollfd));
  self->priv->connections = connections_new ();
  self->priv->thread = NULL;
  self->priv->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  setsockopt (self->priv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &sock_optval, sizeof sock_optval);
}

static void
pex_rtmp_server_dispose (GObject * obj)
{
  PexRtmpServer * self = PEX_RTMP_SERVER_CAST (obj);
  close (self->priv->listen_fd);
  G_OBJECT_CLASS (pex_rtmp_server_parent_class)->dispose (obj);
}

static void
pex_rtmp_server_finalize (GObject * obj)
{
  PexRtmpServer * self = PEX_RTMP_SERVER_CAST (obj);
  g_free(self->priv->application_name);
  g_array_free (self->priv->poll_table, TRUE);
  g_slist_free (self->priv->clients);
  connections_free (self->priv->connections);
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
    case PROP_PORT:
      g_value_set_int (value, self->priv->port);
      break;
    case PROP_APPLICATION_NAME:
      g_value_set_string (value, self->priv->application_name);
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

  g_object_class_install_property (
    gobject_class,
    PROP_APPLICATION_NAME,
    g_param_spec_string ("application-name",
                         "",
                         "",
                         DEFAULT_APPLICATION_NAME,
                         G_PARAM_CONSTRUCT_ONLY |
                         G_PARAM_READWRITE |
                         G_PARAM_STATIC_STRINGS));


  g_object_class_install_property (
    gobject_class,
    PROP_PORT,
    g_param_spec_int ("port",
                      "",
                      "",
                      0,
                      65535,
                      DEFAULT_PORT,
                      G_PARAM_CONSTRUCT_ONLY |
                      G_PARAM_READWRITE |
                      G_PARAM_STATIC_STRINGS));

  signals[SIGNAL_ON_PLAY] = g_signal_new ("on-play",
      PEX_TYPE_RTMP_SERVER, G_SIGNAL_RUN_LAST,
      0, NULL, NULL,
      g_cclosure_marshal_generic, G_TYPE_INT, 1, G_TYPE_STRING);
  signals[SIGNAL_ON_PLAY_DONE] = g_signal_new ("on-play-done",
      PEX_TYPE_RTMP_SERVER, G_SIGNAL_RUN_LAST,
      0, NULL, NULL,
      g_cclosure_marshal_generic, G_TYPE_INT, 1, G_TYPE_STRING);
  signals[SIGNAL_ON_PUBLISH] = g_signal_new ("on-publish",
      PEX_TYPE_RTMP_SERVER, G_SIGNAL_RUN_LAST,
      0, NULL, NULL,
      g_cclosure_marshal_generic, G_TYPE_INT, 1, G_TYPE_STRING);
  signals[SIGNAL_ON_PUBLISH_DONE] = g_signal_new ("on-publish-done",
      PEX_TYPE_RTMP_SERVER, G_SIGNAL_RUN_LAST,
      0, NULL, NULL,
      g_cclosure_marshal_generic, G_TYPE_INT, 1, G_TYPE_STRING);

  g_type_class_add_private (gobject_class, sizeof (PexRtmpServerPrivate));
}


// Helper functions
//
//
//
//
//
//

static int
set_nonblock (int fd, gboolean enabled)
{
  int flags = fcntl (fd, F_GETFL) & ~O_NONBLOCK;
  if (enabled) {
    flags |= O_NONBLOCK;
  }
  return fcntl (fd, F_SETFL, flags);
}

static size_t
recv_all (int fd, void *buf, size_t len)
{
  size_t pos = 0;
  while (pos < len) {
    ssize_t bytes = recv (fd, (char *) buf + pos, len - pos, 0);
    if (bytes < 0) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      g_warning ("unable to recv: %s", strerror (errno));
      return bytes;
    }
    if (bytes == 0)
      break;
    pos += bytes;
  }
  return pos;
}

static size_t
send_all (int fd, const void *buf, size_t len)
{
  size_t pos = 0;
  while (pos < len) {
    ssize_t written = send (fd, (const char *) buf + pos, len - pos, MSG_NOSIGNAL);
    if (written < 0) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      printf("unable to send: %s\n", strerror (errno));
      return written;
    }
    if (written == 0)
      break;
    pos += written;
  }
  return pos;
}

static gboolean
rtmp_server_handshake_client (gint fd)
{
  Handshake serversig;
  Handshake clientsig;
  guint8 c;

  if (recv_all (fd, &c, 1) < 1)
    return FALSE;
  if (c != HANDSHAKE_PLAINTEXT) {
    g_warning ("only plaintext handshake supported");
    return FALSE;
  }

  if (send_all (fd, &c, 1) < 1)
    return FALSE;

  memset (&serversig, 0, sizeof serversig);
  serversig.flags[0] = 0x03;
  for (int i = 0; i < RANDOM_LEN; ++i) {
    serversig.random[i] = rand ();
  }

  if (send_all (fd, &serversig, sizeof serversig) < sizeof serversig)
    return FALSE;

  /* Echo client's signature back */
  if (recv_all (fd, &clientsig, sizeof serversig) < sizeof serversig)
    return FALSE;
  if (send_all (fd, &clientsig, sizeof serversig) < sizeof serversig)
    return FALSE;

  if (recv_all (fd, &clientsig, sizeof serversig) < sizeof serversig)
    return FALSE;
  if (memcmp (serversig.random, clientsig.random, RANDOM_LEN) != 0) {
    printf ("invalid handshake\n");
    return FALSE;
  }

  //client->read_seq = 1 + sizeof serversig * 2;
  //client->written_seq = 1 + sizeof serversig * 2;

  return TRUE;
}


static void
rtmp_server_create_client (PexRtmpServer * srv)
{
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof sin;
  int fd = accept (srv->priv->listen_fd, (struct sockaddr *)&sin, &addrlen);
  if (fd < 0) {
    printf ("Unable to accept a client: %s\n", strerror (errno));
    return;
  }

  /* handshake */
  if (!rtmp_server_handshake_client (fd)) {
    printf ("Hanshake Failed\n");
    close (fd);
    return;
  }

  /* make the connection non-blocking */
  set_nonblock (fd, TRUE);

  /* create and add client */
  Client * client = client_new (fd, srv->priv->connections, G_OBJECT(srv));
  srv->priv->clients = g_slist_append (srv->priv->clients, client);

  printf ("adding client %p\n", client);

  /* update poll table */
  struct pollfd entry;
  entry.events = POLLIN;
  entry.revents = 0;
  entry.fd = fd;
  srv->priv->poll_table = g_array_append_val (srv->priv->poll_table, entry);
}

static void
rtmp_server_remove_client (PexRtmpServer * srv, Client * client, size_t i)
{
  int ign;
  if (client->publisher) {
    g_signal_emit_by_name(srv, "on-publish-done", client->path, &ign);
  } else {
    g_signal_emit_by_name(srv, "on-play-done", client->path, &ign);
  }
  srv->priv->clients = g_slist_remove (srv->priv->clients, client);
  srv->priv->poll_table = g_array_remove_index (srv->priv->poll_table, i);

  close (client->fd);
  printf ("removing client %p\n", client);

  connections_remove_client (srv->priv->connections, client, client->path);

  client_free (client);
}

static gboolean
rtmp_server_do_poll (PexRtmpServer * srv)
{
  for (size_t i = 0; i < srv->priv->poll_table->len; ++i) {
    Client * client = (Client *) g_slist_nth_data (srv->priv->clients, i);
    if (client != NULL) {
      struct pollfd * entry = (struct pollfd *)&g_array_index (srv->priv->poll_table, struct pollfd, i);
      if (client->send_queue->len > 0) {
        entry->events = POLLIN | POLLOUT;
      } else {
        entry->events = POLLIN;
      }
    }
  }

  /* waiting for traffic on all connections */
  int timeout = 200; /* 200 ms second */
  if (poll ((struct pollfd *)&srv->priv->poll_table->data[0], srv->priv->poll_table->len, timeout) < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    g_warning ("poll() failed: %s", strerror (errno));
    return FALSE;
  }

  if (srv->priv->running == FALSE)
    return FALSE;

  for (size_t i = 0; i < srv->priv->poll_table->len; ++i) {
    struct pollfd * entry = (struct pollfd *)&g_array_index (srv->priv->poll_table, struct pollfd, i);
    Client * client = (Client *) g_slist_nth_data (srv->priv->clients, i);

    /* ready to send */
    if (entry->revents & POLLOUT) {
      if (!client_try_to_send (client)) {
        printf ("client error, send failed\n");
        rtmp_server_remove_client (srv, client, i);
        --i;
        continue;
      }
    }
    /* data to receive */
    if (entry->revents & POLLIN) {
      if (client == NULL) {
        rtmp_server_create_client (srv);
      } else if (!client_receive (client)) {
        printf ("client error: client_recv_from_client failed\n");
        rtmp_server_remove_client (srv, client, i);
        --i;
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

#ifdef __APPLE__
  signal (SIGPIPE, SIG_IGN);
#endif

  while (srv->priv->running && ret) {
    ret = rtmp_server_do_poll (srv);
  }

  /* remove outstanding clients */
  for (size_t i = 0; i < srv->priv->poll_table->len; ++i) {
    Client * client = (Client *)g_slist_nth_data (srv->priv->clients, i);
    if (client) {
      rtmp_server_remove_client (srv, client, i);
      --i;
    }
  }

  return NULL;
}

gboolean
pex_rtmp_server_start (PexRtmpServer * srv)
{
  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons (srv->priv->port);
  sin.sin_addr.s_addr = INADDR_ANY;
  g_assert_cmpint (srv->priv->listen_fd, >=, 0);

  if (bind (srv->priv->listen_fd, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
    g_warning ("Unable to listen: %s", strerror (errno));
    return FALSE;
  }

  listen (srv->priv->listen_fd, 10);

  struct pollfd entry;
  entry.events = POLLIN;
  entry.revents = 0;
  entry.fd = srv->priv->listen_fd;
  srv->priv->poll_table = g_array_append_val (srv->priv->poll_table, entry);

  /* FIXME: inserting NULL client is silly... */
  srv->priv->clients = g_slist_append (srv->priv->clients, NULL);

  srv->priv->running = TRUE;
  srv->priv->thread = g_thread_new ("RTMPServer", rtmp_server_func, srv);
  return TRUE;
}

void
pex_rtmp_server_stop (PexRtmpServer * srv)
{
  printf ("Stopping...\n");
  srv->priv->running = FALSE;
  g_thread_join (srv->priv->thread);
}

void pex_rtmp_server_free(PexRtmpServer * srv)
{
  g_object_unref(srv);
}
