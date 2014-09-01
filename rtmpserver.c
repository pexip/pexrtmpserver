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

struct _RTMPServer
{
  gint listen_fd;
  GHashTable * publishers;
  GHashTable * subscriber_lists;
  char * application_name;
  GArray * poll_table;
  GSList * clients;
  gboolean running;
  GThread * thread;

  Connections * connections;
};

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
    ssize_t written = send (fd, (const char *) buf + pos, len - pos, 0);
    if (written < 0) {
      if (errno == EAGAIN || errno == EINTR)
        continue;
      g_warning ("unable to send: %s", strerror (errno));
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
    g_warning ("invalid handshake");
    return FALSE;
  }

  //client->read_seq = 1 + sizeof serversig * 2;
  //client->written_seq = 1 + sizeof serversig * 2;

  return TRUE;
}


static void
rtmp_server_create_client (RTMPServer * srv)
{
  struct sockaddr_in sin;
  socklen_t addrlen = sizeof sin;
  int fd = accept (srv->listen_fd, (struct sockaddr *)&sin, &addrlen);
  if (fd < 0) {
    g_warning ("Unable to accept a client: %s\n", strerror (errno));
    return;
  }

  /* handshake */
  if (!rtmp_server_handshake_client (fd)) {
    g_warning ("Hanshake Failed");
    close (fd);
    return;
  }

  /* make the connection non-blocking */
  set_nonblock (fd, TRUE);

  /* create and add client */
  Client * client = client_new (fd, srv->connections);
  srv->clients = g_slist_append (srv->clients, client);

  printf ("adding client %p\n", client);

  /* update poll table */
  struct pollfd entry;
  entry.events = POLLIN;
  entry.revents = 0;
  entry.fd = fd;
  srv->poll_table = g_array_append_val (srv->poll_table, entry);
}

static void
rtmp_server_remove_client (RTMPServer * srv, Client * client, size_t i)
{
  srv->clients = g_slist_remove (srv->clients, client);
  srv->poll_table = g_array_remove_index (srv->poll_table, i);

  close (client->fd);
  printf ("removing client %p\n", client);

  connections_remove_client (srv->connections, client, client->path);

  client_free (client);
}

static gboolean
rtmp_server_do_poll (RTMPServer * srv)
{
  for (size_t i = 0; i < srv->poll_table->len; ++i) {
    Client * client = (Client *) g_slist_nth_data (srv->clients, i);
    if (client != NULL) {
      struct pollfd * entry = (struct pollfd *)&g_array_index (srv->poll_table, struct pollfd, i);
      if (client->send_queue->len > 0) {
        entry->events = POLLIN | POLLOUT;
      } else {
        entry->events = POLLIN;
      }
    }
  }

  /* waiting for traffic on all connections */
  int timeout = 200; /* 200 ms second */
  if (poll ((struct pollfd *)&srv->poll_table->data[0], srv->poll_table->len, timeout) < 0) {
    if (errno == EAGAIN || errno == EINTR)
      return TRUE;
    g_warning ("poll() failed: %s", strerror (errno));
    return FALSE;
  }

  if (srv->running == FALSE)
    return FALSE;

  for (size_t i = 0; i < srv->poll_table->len; ++i) {
    struct pollfd * entry = (struct pollfd *)&g_array_index (srv->poll_table, struct pollfd, i);
    Client * client = (Client *) g_slist_nth_data (srv->clients, i);

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
  RTMPServer * srv = (RTMPServer *)data;
  gboolean ret = TRUE;

#ifdef __APPLE__
  signal (SIGPIPE, SIG_IGN);
#endif

  while (srv->running && ret) {
    ret = rtmp_server_do_poll (srv);
  }

  /* remove outstanding clients */
  for (size_t i = 0; i < srv->poll_table->len; ++i) {
    Client * client = (Client *)g_slist_nth_data (srv->clients, i);
    if (client) {
      rtmp_server_remove_client (srv, client, i);
      --i;
    }
  }

  return NULL;
}

void
rtmp_server_start (RTMPServer * srv)
{
  printf ("Starting...\n");
  srv->running = TRUE;
  srv->thread = g_thread_new ("RTMPServer", rtmp_server_func, srv);
}

void
rtmp_server_stop (RTMPServer * srv)
{
  printf ("Stopping...\n");
  srv->running = FALSE;
  g_thread_join (srv->thread);
}

RTMPServer *
rtmp_server_new (const gchar * application_name, gint port)
{
  RTMPServer * srv = g_new0 (RTMPServer, 1);

  srv->listen_fd = socket (AF_INET, SOCK_STREAM, 0);
  int optval = 1;
  setsockopt (srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
  if (srv->listen_fd < 0) {
    return NULL;
  }

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  sin.sin_addr.s_addr = INADDR_ANY;
  if (bind (srv->listen_fd, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
    g_warning ("Unable to listen: %s", strerror (errno));
    return NULL;
  }

  listen (srv->listen_fd, 10);

  srv->application_name = g_strdup (application_name);
  srv->poll_table = g_array_new (FALSE, TRUE, sizeof (struct pollfd));
  srv->connections = connections_new ();

  struct pollfd entry;
  entry.events = POLLIN;
  entry.revents = 0;
  entry.fd = srv->listen_fd;
  srv->poll_table = g_array_append_val (srv->poll_table, entry);

  /* FIXME: inserting NULL client is silly... */
  srv->clients = g_slist_append (srv->clients, NULL);

  return srv;
}

void
rtmp_server_free (RTMPServer * srv)
{
  close (srv->listen_fd);
  connections_free (srv->connections);
  g_free (srv->application_name);
  g_array_free (srv->poll_table, TRUE);
  g_slist_free (srv->clients);
  g_free (srv);
}
