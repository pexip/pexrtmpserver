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
#include "tcp.h"

#ifdef G_OS_WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <windows.h>
#  include <Ws2ipdef.h>
#  include <Ws2tcpip.h>
#else
#  include <fcntl.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <netdb.h>
#  include <netinet/tcp.h>
#endif

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

void
tcp_set_nonblock (gint fd, gboolean enabled)
{
#ifdef _MSC_VER
  u_long arg = enabled ? 1 : 0;
  ioctlsocket (fd, FIONBIO, &arg);
#else
  gint flags = fcntl (fd, F_GETFL) & ~O_NONBLOCK;
  if (enabled) {
    flags |= O_NONBLOCK;
  }
  fcntl (fd, F_SETFL, flags);
#endif /* _MSC_VER */
}

static void
_close_socket (int fd)
{
#ifdef _MSC_VER
  closesocket (fd);
#else
  close (fd);
#endif
}

static gchar *
get_error_msg ()
{
#if defined(_MSC_VER)
  gchar msgbuf [256];
  msgbuf [0] = '\0';

  gint err = WSAGetLastError ();
  FormatMessage (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, err, MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT),
      msgbuf, sizeof (msgbuf), NULL);
  return g_strdup (msgbuf);
#else
  return g_strdup (g_strerror (errno));
#endif
}

gchar *
get_url_from_sockaddr_storage (const struct sockaddr_storage * addr)
{
  gchar *ret = NULL;
  gchar ip[INET6_ADDRSTRLEN];

  if (addr->ss_family == AF_INET) {
    struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
    inet_ntop (AF_INET, &addr_in->sin_addr, ip, 100);
    ret = g_strdup_printf ("%s:%d", ip, ntohs (addr_in->sin_port));
  } else {
    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
    inet_ntop (AF_INET6, &addr_in6->sin6_addr, ip, 100);
    ret = g_strdup_printf ("%s:%d", ip, ntohs (addr_in6->sin6_port));
  }

  return ret;
}

gchar *
get_url_from_addrinfo (const struct addrinfo * ai)
{
  return get_url_from_sockaddr_storage (
      (const struct sockaddr_storage *)ai->ai_addr);
}

static gint
tcp_getaddrinfo (const gchar * ip, gint port,
    gint ai_family, gint ai_flags, struct addrinfo ** result)
{
  struct addrinfo hints;
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = ai_family;
  hints.ai_socktype = SOCK_STREAM; /* Stream soc */
  hints.ai_protocol = IPPROTO_TCP; /* TCP protocol */
  hints.ai_flags = ai_flags;

  gchar *port_str = NULL;
  if (port > 0) {
    port_str = g_strdup_printf ("%d", port);
    hints.ai_flags |= AI_NUMERICSERV;
  }
  int ret = getaddrinfo (ip, port_str, &hints, result);
  g_free (port_str);
  if (ret != 0) {
    gchar *errmsg = get_error_msg ();
    GST_WARNING ("getaddrinfo returned: %d (%s)", ret, errmsg);
    g_free (errmsg);
  }
  return ret;
}

static gint
_create_socket (const struct addrinfo * ai)
{
  gint fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0) {
    gchar *errmsg = get_error_msg ();
    GST_WARNING ("socket returned: %s", errmsg);
    g_free (errmsg);
  }
  return fd;
}

gboolean
tcp_connect (gint * fd, const gchar * ip,
    gint port, gint src_port, gint tcp_syncnt)
{
  struct addrinfo *result = NULL;
  int ret = tcp_getaddrinfo (ip, port, AF_UNSPEC, 0, &result);
  if (ret != 0) {
    *fd = INVALID_FD;
    goto done;
  }
  if (result == NULL) {
    GST_WARNING ("getaddrinfo result was NULL");
    *fd = INVALID_FD;
    goto done;
  }

//  struct addrinfo *ai_ptr = NULL;
//  for (ai_ptr = result; ai_ptr != NULL ; ai_ptr = ai_ptr->ai_next)
//    GST_INFO ("connect result: %s", get_url_from_addrinfo (ai_ptr));

  *fd = _create_socket (result);
  if (*fd < 0) {
    *fd = INVALID_FD;
    goto done;
  }

  /* set timeout */
  struct timeval tv = { 30, 0 };
  if (setsockopt (*fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof (tv))) {
    GST_WARNING ("Could not set timeout");
  }
  /* Disable packet-accumulation delay (Nagle's algorithm) */
  int value = 1;
  if (setsockopt (*fd, IPPROTO_TCP, TCP_NODELAY, (char *)&value, sizeof (value)))
    GST_WARNING ("Could not set TCP_NODELAY: %s", get_error_msg ());

#if !defined (_MSC_VER)
  /* Allow reuse of the local address */
  value = 1;
  if (setsockopt (*fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof (value)))
    GST_WARNING ("Could not set SO_REUSEADDR: %s", get_error_msg ());

  /* Configure TCP_SYNCNT */
  if (tcp_syncnt >= 0) {
#ifdef TCP_SYNCNT
    value = tcp_syncnt;
    setsockopt (*fd, IPPROTO_TCP, TCP_SYNCNT, (char *) &value, sizeof (value));
#endif /* TCP_SYNCNT */
  }
#endif /* _MSC_VER */

  if (src_port) {
    GST_DEBUG ("Connecting to %s:%d from %d", ip, port, src_port);

    struct addrinfo *src_res = NULL;
    ret = tcp_getaddrinfo (NULL, src_port,
        result->ai_family, AI_NUMERICHOST | AI_PASSIVE, &src_res);
    if (ret < 0) {
      *fd = INVALID_FD;
      goto done;
    }

    //for (ai_ptr = src_res; ai_ptr != NULL ; ai_ptr = ai_ptr->ai_next)
    //  GST_INFO ("bind result: %s", get_url_from_addrinfo (ai_ptr));

    ret = bind (*fd, src_res->ai_addr, (int)src_res->ai_addrlen);
    freeaddrinfo (src_res);

    if (ret < 0) {
      GST_WARNING ("Unable to bind to port %d: %s", src_port, strerror (errno));
      _close_socket (*fd);
      *fd = INVALID_FD;
      goto done;
    }
  }

  ret = connect (*fd, result->ai_addr, (int)result->ai_addrlen);

  if (ret != 0 && errno != EINPROGRESS) {
    GST_WARNING ("could not connect on port %d: %s", port, g_strerror (errno));
    _close_socket (*fd);
    *fd = INVALID_FD;
    goto done;
  }

  /* make the connection non-blocking */
  tcp_set_nonblock (*fd, TRUE);

done:
  freeaddrinfo (result);
  return *fd != INVALID_FD;
}

gint
tcp_listen (gint port)
{
  gint fd;
  int val;
  struct addrinfo *result = NULL;

  int ret = tcp_getaddrinfo (NULL, port,
      AF_INET6, AI_PASSIVE, &result);
  if (ret != 0) {
    fd = INVALID_FD;
    goto done;
  }

/*
  struct addrinfo *ai_ptr = NULL;
  for (ai_ptr = result; ai_ptr != NULL ; ai_ptr = ai_ptr->ai_next) {
    GST_INFO ("listen result: %s", get_url_from_addrinfo (ai_ptr));
  }
*/

  fd = _create_socket (result);
  if (fd < 0) {
    fd = INVALID_FD;
    goto done;
  }

#if !defined (_MSC_VER)
  val = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &val, sizeof (val)))
    GST_WARNING ("Could not set SO_REUSEADDR: %s", get_error_msg ());
#endif

  val = 0;
  if (setsockopt (fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &val, sizeof (val)))
    GST_WARNING ("Could not turn off IPV6_V6ONLY: %s", get_error_msg ());

  if (bind (fd, result->ai_addr, (int)result->ai_addrlen) < 0) {
    GST_WARNING ("Unable to listen to port %d: %s",
        port, strerror (errno));
    _close_socket (fd);
    fd = INVALID_FD;
    goto done;
  }

  listen (fd, 10);
  GST_DEBUG ("Listening on port %d with fd %d", port, fd);

done:
  freeaddrinfo (result);
  return fd;
}

gint
tcp_accept (gint listen_fd)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof (struct sockaddr_storage);
  gint fd =  accept (listen_fd, (struct sockaddr *)&addr, &len);
  if (fd < 0) {
    GST_WARNING ("Could not accept: %s", get_error_msg ());
  } else {
    gchar *url = get_url_from_sockaddr_storage (&addr);
    GST_INFO ("Accepted connection from %s", url);
    g_free (url);
  }

  return fd;
}

void
tcp_disconnect (gint fd)
{
#ifdef _MSC_VER
  shutdown (fd, SD_BOTH);
#else
  shutdown (fd, SHUT_RDWR);
#endif

  struct linger linger;
  linger.l_onoff = 1;
  linger.l_linger = 0;
  setsockopt (fd, SOL_SOCKET, SO_LINGER, (char *)&linger, sizeof (linger));

  _close_socket (fd);
}

gboolean
tcp_is_localhost (gint fd)
{
  struct sockaddr_storage addr;
  struct sockaddr_in6 *sin6;
  struct sockaddr_in *sin;
  socklen_t len = sizeof (addr);
  gchar ipstr[INET6_ADDRSTRLEN];
  gboolean is_localhost = FALSE;

  if (getpeername (fd, (struct sockaddr *) &addr, &len) == 0) {
    if (addr.ss_family == AF_INET) {
      sin = (struct sockaddr_in *) &addr;
      inet_ntop (AF_INET, &sin->sin_addr, ipstr, sizeof (ipstr));
    } else {
      sin6 = (struct sockaddr_in6 *) &addr;
      inet_ntop (AF_INET6, &sin6->sin6_addr, ipstr, sizeof ipstr);
    }
    is_localhost = g_strcmp0 (ipstr, "::1") == 0 ||
        g_strcmp0 (ipstr, "::ffff:127.0.0.1") == 0 ||
        g_strcmp0 (ipstr, "127.0.0.1") == 0;
  }

  return is_localhost;
}
