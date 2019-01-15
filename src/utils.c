#include "utils.h"
#include "rtmpserver.h"
#include "rtmp.h"

#if defined(HOST_LINUX)
#  include <linux/sockios.h>
#endif

#if defined(_MSC_VER)
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

#include <openssl/pem.h>

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

/*
 * Used to do unaligned loads on archs that don't support them. GCC can mostly
 * optimize these away.
 */
guint32
load_be32 (const void *p)
{
  guint32 val = *((guint32 *) p);
  return GUINT32_FROM_BE (val);
}

guint16
load_be16 (const void *p)
{
  guint16 val = *((guint16 *) p);
  return GUINT16_FROM_BE (val);
}

guint32
load_le32 (const void *p)
{
  guint32 val = *((guint32 *) p);
  return val;
}

guint32
load_be24 (const void *p)
{
  const guint8 *data = (const guint8 *) p;
  return data[2] | ((guint32) data[1] << 8) | ((guint32) data[0] << 16);
}

void
set_be24 (void *p, guint32 val)
{
  guint8 *data = (guint8 *) p;
  data[0] = val >> 16;
  data[1] = val >> 8;
  data[2] = val;
}

void
set_le32 (void *p, guint32 val)
{
  guint8 *data = (guint8 *) p;
  data[0] = val;
  data[1] = val >> 8;
  data[2] = val >> 16;
  data[3] = val >> 24;
}

void
set_be32 (void *p, guint32 val)
{
  guint8 *data = (guint8 *) p;
  data[0] = val >> 24;
  data[1] = val >> 16;
  data[2] = val >> 8;
  data[3] = val;
}

/*
typedef struct
{
  guint8 packet_type;
  guint8 payload_size[3];
  guint8 timestamp[4];
  guint8 stream_id[3];
} FLVPacketHeader;
*/

static const guint flv_tag_header_size = 11;
static const gchar flv_header[] = {
    'F', 'L', 'V',
    0x01, /* version 1 */
    0x05, /* audio and video */
    0x00, 0x00, 0x00, 0x09, /* 9 bytes header */
    0x00, 0x00, 0x00, 0x00, /* cheating, putting PreviousTagSize0 here */
};

guint
parse_flv_header (const guint8 * data)
{
  /* could use this to "turn on" publishing ? */
  if (data[0] == 'F' && data[1] == 'L' && data[2] == 'V' && data[3] == 0x01)
    return sizeof (flv_header);

  return 0;
}

guint
parse_flv_tag (const guint8 * data, guint size,
    guint8 * packet_type, guint * payload_size, guint * timestamp)
{
  if (size < flv_tag_header_size)
    return 0;

  *packet_type = data[0];
  *payload_size = load_be24 (&data[1]);
  *timestamp = load_be24 (&data[4]) | (data[7] << 24);
  return flv_tag_header_size;
}

GstBuffer *
generate_flv_header ()
{
  guint8 *data = g_malloc (sizeof (flv_header));
  memcpy (data, flv_header, sizeof (flv_header));
  return gst_buffer_new_wrapped (data, sizeof (flv_header));
}

static void
write_flv_tag (guint8 * data,
    guint8 packet_type, guint payload_size, guint32 timestamp)
{
  data[0] = packet_type;
  set_be24 (&data[1], payload_size);

  if (timestamp > EXT_TIMESTAMP_LIMIT) {
    set_be32 (&data[4], timestamp);
  } else {
    set_be24 (&data[4], timestamp);
    data[7] = 0;
  }
  set_be24 (&data[8], 0);
}

GstBuffer *
generate_flv_tag (const guint8 * data, gsize size, guint8 id, guint32 timestamp)
{
  guint size_with_header = size + flv_tag_header_size;
  guint tag_size = size_with_header + 4;
  guint8 *tag = g_malloc (tag_size);

  write_flv_tag (tag, id, size, timestamp);

  memcpy (&tag[flv_tag_header_size], data, size);

  /* write the total length (size_with_header) in the last 4 bytes */
  set_be32 (&tag[size_with_header], size_with_header);

  return gst_buffer_new_wrapped (tag, tag_size);
}


void
tcp_set_nonblock (int fd, gboolean enabled)
{
#ifdef _MSC_VER
  u_long arg = enabled ? 1 : 0;
  ioctlsocket (fd, FIONBIO, &arg);
#else
  int flags = fcntl (fd, F_GETFL) & ~O_NONBLOCK;
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
  gchar ip[256];

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
  if (port > 0)
    port_str = g_strdup_printf ("%d", port);
  int ret = getaddrinfo (ip, port_str, &hints, result);
  g_free (port_str);
  if (ret != 0) {
    gchar *errmsg = get_error_msg ();
    GST_WARNING ("getaddrinfo returned: %s", errmsg);
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

gint
tcp_connect (const gchar * ip, gint port, gint src_port, gint tcp_syncnt)
{
  int fd;

  struct addrinfo *result = NULL;
  int ret = tcp_getaddrinfo (ip, port, AF_UNSPEC, AI_NUMERICHOST, &result);
  if (ret != 0) {
    fd = INVALID_FD;
    goto done;
  }
  if (result == NULL) {
    GST_WARNING ("getaddrinfo result was NULL");
    fd = INVALID_FD;
    goto done;
  }

//  struct addrinfo *ai_ptr = NULL;
//  for (ai_ptr = result; ai_ptr != NULL ; ai_ptr = ai_ptr->ai_next)
//    GST_INFO ("connect result: %s", get_url_from_addrinfo (ai_ptr));

  fd = _create_socket (result);
  if (fd < 0) {
    fd = INVALID_FD;
    goto done;
  }

  /* set timeout */
  struct timeval tv = { 30, 0 };
  if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof (tv))) {
    GST_WARNING ("Could not set timeout");
  }
  /* Disable packet-accumulation delay (Nagle's algorithm) */
  int value = 1;
  if (setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (char *)&value, sizeof (value)))
    GST_WARNING ("Could not set TCP_NODELAY: %s", get_error_msg ());

#if !defined (_MSC_VER)
  /* Allow reuse of the local address */
  value = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof (value)))
    GST_WARNING ("Could not set SO_REUSEADDR: %s", get_error_msg ());

  /* Configure TCP_SYNCNT */
  if (tcp_syncnt >= 0) {
#ifdef TCP_SYNCNT
    value = tcp_syncnt;
    setsockopt (fd, IPPROTO_TCP, TCP_SYNCNT, (char *) &value, sizeof (value));
#endif /* TCP_SYNCNT */
  }
#endif /* _MSC_VER */

  if (src_port) {
    GST_DEBUG ("Connecting to %s:%d from %d", ip, port, src_port);

    struct addrinfo *src_res = NULL;
    ret = tcp_getaddrinfo (NULL, src_port,
        result->ai_family, AI_NUMERICHOST | AI_PASSIVE, &src_res);
    if (ret < 0) {
      fd = INVALID_FD;
      goto done;
    }

    //for (ai_ptr = src_res; ai_ptr != NULL ; ai_ptr = ai_ptr->ai_next)
    //  GST_INFO ("bind result: %s", get_url_from_addrinfo (ai_ptr));

    ret = bind (fd, src_res->ai_addr, (int)src_res->ai_addrlen);
    freeaddrinfo (src_res);

    if (ret < 0) {
      GST_WARNING ("Unable to bind to port %d: %s", src_port, strerror (errno));
      _close_socket (fd);
      fd = INVALID_FD;
      goto done;
    }
  }

#if 1
  ret = connect (fd, result->ai_addr, (int)result->ai_addrlen);
#else
  if (result->ai_family == AF_INET) {
     struct sockaddr_in *a_in = (struct sockaddr_in *)result->ai_addr;
     a_in->sin_port = htons (port);
     ret = connect (fd, (struct sockaddr *)a_in, sizeof (struct sockaddr_in));
   } else {
     struct sockaddr_in6 *a_in = (struct sockaddr_in6 *)result->ai_addr;
     a_in->sin6_port = htons (port);
     ret = connect (fd, (struct sockaddr *)a_in, sizeof (struct sockaddr_in6));
   }
#endif

  if (ret != 0 && errno != EINPROGRESS) {
    GST_WARNING ("could not connect on port %d: %s", port, g_strerror (errno));
    _close_socket (fd);
    fd = INVALID_FD;
    goto done;
  }

  /* make the connection non-blocking */
  tcp_set_nonblock (fd, TRUE);

done:
  freeaddrinfo (result);
  return fd;
}

gint
tcp_listen (gint port)
{
  gint fd;
  int val;
  struct addrinfo *result = NULL;

  int ret = tcp_getaddrinfo (NULL, port,
      AF_INET6, AI_NUMERICHOST | AI_PASSIVE, &result);
  if (ret != 0) {
    fd = INVALID_FD;
    goto done;
  }

  struct addrinfo *ai_ptr = NULL;
  for (ai_ptr = result; ai_ptr != NULL ; ai_ptr = ai_ptr->ai_next) {
    GST_INFO ("listen result: %s", get_url_from_addrinfo (ai_ptr));
  }

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

static gint
count_chars_in_string (const gchar * s, char c)
{
  gint ret;
  for (ret = 0; s[ret]; s[ret] == c ? ret++ : *(s++));
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

gboolean
parse_rtmp_url (const gchar * url,
    gchar ** protocol, gint * port, gchar ** ip, gchar ** application_name,
    gchar ** path, gchar ** username, gchar ** password)
{
  gboolean ret = TRUE;

  gchar **space_clip = NULL;
  gchar **protocol_clip = NULL;
  gchar **at_clip = NULL;
  gchar **credential_clip = NULL;
  gchar **slash_clip = NULL;
  gchar **address_clip = NULL;

  *protocol = NULL;
  *port = 0;
  *ip = NULL;
  *application_name = NULL;
  *path = NULL;
  *username = NULL;
  *password = NULL;

  /* start by clipping off anything on the end (live=1) */
  space_clip = g_strsplit (url, " ", 1024);
  const gchar *url_nospace = space_clip[0];

  if (url_nospace == NULL) {
    GST_WARNING ("Unable to parse");
    ret = FALSE;
    goto done;
  }

  /* then clip before and after protocol (rtmp://) */
  protocol_clip = g_strsplit (url_nospace, "://", 1024);
  const gchar *protocol_tmp = protocol_clip[0];
  const gchar *the_rest = protocol_clip[1];
  if (!(protocol_tmp && the_rest && (g_strcmp0 (protocol_tmp, "rtmp") == 0
              || g_strcmp0 (protocol_tmp, "rtmps") == 0))) {
    GST_WARNING ("Unable to parse");
    ret = FALSE;
    goto done;
  }

  /* clip all "/" bits */
  slash_clip = g_strsplit (the_rest, "/", 1024);
  gint idx = 0;
  while (slash_clip[idx] != NULL)
    idx++;
  if (idx < 3) {
    GST_WARNING ("Not able to find address, application_name and path");
    ret = FALSE;
    goto done;
  }

  /* clip IP and port */
  const gchar *address = slash_clip[0];

  /* check for credentials */
  gint num_ats = count_chars_in_string (address, '@');
  if (num_ats > 0) {
    at_clip = g_strsplit (address, "@", 2);
    const gchar *credentials = at_clip[0];
    address = at_clip[1];
    credential_clip = g_strsplit (credentials, ":", 1024);
    if (credential_clip[0] && credential_clip[1]) {
      *username = g_strdup (credential_clip[0]);
      *password = g_strdup (credential_clip[1]);
    } else {
      GST_WARNING ("Could not find both username and password");
      ret = FALSE;
      goto done;
    }
  }

  gint num_colons = count_chars_in_string (address, ':');
  if (num_colons > 1) {         /* ipv6 */
    address_clip = g_strsplit (address, "]:", 1024);

    if (!get_port_from_string (address_clip[1], port)) {
      GST_WARNING ("Specify the port, buster!");
      ret = FALSE;
      goto done;
    }

    if (address_clip[1] != NULL) {
      *ip = g_strdup (&address_clip[0][1]);     /* remove the the beginning '[' */
    } else {
      *ip = g_strdup (address);
    }
  } else {                      /* ipv4 */
    address_clip = g_strsplit (address, ":", 1024);
    if (!get_port_from_string (address_clip[1], port)) {
      GST_WARNING ("Specify the port, buster!");
      ret = FALSE;
      goto done;
    }
    *ip = g_strdup (address_clip[0]);
  }

  *protocol = g_strdup (protocol_tmp);
  *path = g_strdup (slash_clip[idx - 1]);       /* path is last */
  *application_name = g_strndup (&the_rest[strlen (slash_clip[0]) + 1],
      strlen (the_rest) - strlen (slash_clip[0]) - strlen (*path) - 2);

  GST_INFO ("Parsed: Protocol: %s, Ip: %s, Port: %d, "
      "Application Name: %s, Path: %s, Username: %s, Password: %s",
      *protocol, *ip, *port, *application_name, *path, *username, *password);

done:
  g_strfreev (space_clip);
  g_strfreev (protocol_clip);
  g_strfreev (at_clip);
  g_strfreev (credential_clip);
  g_strfreev (slash_clip);
  g_strfreev (address_clip);

  return ret;
}

static int
match_dns_name (const gchar * remote_host, ASN1_IA5STRING * candidate)
{
  const gchar *data = (gchar *) ASN1_STRING_data (candidate);
  int len = ASN1_STRING_length (candidate);
  int host_len = strlen (remote_host);

  if ((int) strnlen (data, len) != len) {
    /* Candidate contains embedded NULs: reject it */
    return 0;
  }

  /* See RFC6125 $6.4. We assume that any IDN has been pre-normalised
   * to remove any U-labels. */
  if (len == host_len && g_ascii_strncasecmp (remote_host, data, len) == 0) {
    /* Exact match */
    return 1;
  }

  if (g_hostname_is_ip_address (remote_host)) {
    /* Do not attempt to match wildcards against IP addresses */
    return 0;
  }

  /* Wildcards: permit the left-most label to be '*' only and match
   * the left-most reference label */
  if (len > 1 && data[0] == '*' && data[1] == '.') {
    const gchar *host_suffix = strchr (remote_host, '.');
    if (host_suffix == NULL || host_suffix == remote_host) {
      /* No dot found, or remote_host starts with a dot: reject */
      return 0;
    }

    if (len - 1 == host_len - (host_suffix - remote_host) &&
        g_ascii_strncasecmp (host_suffix, data + 1, len - 1) == 0) {
      /* Wildcard matched */
      return 1;
    }
  }

  return 0;
}

static int
match_subject_alternative_names (X509 * cert, const gchar * remote_host)
{
  int result = -1;
  GENERAL_NAMES *san;

  san = X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);
  if (san != NULL) {
    int idx = sk_GENERAL_NAME_num (san);
    enum
    {
      HOST_TYPE_DNS = 0,
      HOST_TYPE_IPv4 = sizeof (struct in_addr),
      HOST_TYPE_IPv6 = sizeof (struct in6_addr)
    } host_type;
    int num_sans_for_type = 0;
    struct in6_addr addr;

    if (inet_pton (AF_INET6, remote_host, &addr)) {
      host_type = HOST_TYPE_IPv6;
    } else if (inet_pton (AF_INET, remote_host, &addr)) {
      host_type = HOST_TYPE_IPv4;
    } else {
      host_type = HOST_TYPE_DNS;
    }

    while (--idx >= 0) {
      int type;
      void *value;

      value = GENERAL_NAME_get0_value (sk_GENERAL_NAME_value (san, idx), &type);

      if (type == GEN_DNS && host_type == HOST_TYPE_DNS) {
        num_sans_for_type++;
        if (match_dns_name (remote_host, value)) {
          break;
        }
      } else if (type == GEN_IPADD && host_type != HOST_TYPE_DNS) {
        int len = ASN1_STRING_length (value);
        num_sans_for_type++;
        if (len == (int) host_type &&
            memcmp (ASN1_STRING_data (value), &addr, len) == 0) {
          break;
        }
      }
    }

    GENERAL_NAMES_free (san);

    if (num_sans_for_type > 0) {
      result = (idx >= 0);
    }
  }

  /* -1 if no applicable SANs present; 0 for no match; 1 for match */
  return result;
}

static int
match_subject_common_name (X509 * cert, const gchar * remote_host)
{
  X509_NAME *subject = X509_get_subject_name (cert);

  if (subject != NULL) {
    int idx = X509_NAME_entry_count (subject);

    while (--idx >= 0) {
      X509_NAME_ENTRY *entry = X509_NAME_get_entry (subject, idx);
      if (OBJ_obj2nid (X509_NAME_ENTRY_get_object (entry)) == NID_commonName) {
        return match_dns_name (remote_host, X509_NAME_ENTRY_get_data (entry));
      }
    }
  }

  return 0;
}

int
verify_hostname (X509 * cert, const gchar * remote_host)
{
  /* See RFC2818 $3.1 */
  int result = match_subject_alternative_names (cert, remote_host);

  if (result == -1) {
    result = match_subject_common_name (cert, remote_host);
  }

  return result;
}

gboolean
file_exists (const gchar * path)
{
  if (path == NULL || path[0] == '\0') {
    return FALSE;
  }
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

DH *
make_dh_params (const gchar * cert_file)
{
  DH *dh = NULL;
  BIO *bio = BIO_new_file (cert_file, "r");

  if (bio != NULL) {
    X509 *cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
    BIO_free (bio);

    if (cert != NULL) {
      EVP_PKEY *pubkey = X509_get_pubkey (cert);
      if (pubkey != NULL) {
        static const struct
        {
          int size;
          BIGNUM *(*prime) (BIGNUM *);
        } gentable[] = {
          {
          2048, get_rfc3526_prime_2048}, {
          3072, get_rfc3526_prime_3072}, {
          4096, get_rfc3526_prime_4096}, {
          6144, get_rfc3526_prime_6144}, {
          8192, get_rfc3526_prime_8192}
        };
        size_t idx;
        int keylen = 2048;
        int type = EVP_PKEY_type (pubkey->type);
        if (type == EVP_PKEY_RSA || type == EVP_PKEY_DSA) {
          keylen = EVP_PKEY_bits (pubkey);
        }
        EVP_PKEY_free (pubkey);

        for (idx = 0; idx < sizeof (gentable) / sizeof (gentable[0]); idx++) {
          if (keylen <= gentable[idx].size) {
            break;
          }
        }
        if (idx == sizeof (gentable) / sizeof (gentable[0])) {
          idx--;
        }

        dh = DH_new ();
        if (dh != NULL) {
          dh->p = gentable[idx].prime (NULL);
          BN_dec2bn (&dh->g, "2");
          if (dh->p == NULL || dh->g == NULL) {
            DH_free (dh);
            dh = NULL;
          }
        }
      }
      X509_free (cert);
    }
  }

  return dh;
}

static GstStructure *
_map_auth_tokens (const gchar * auth_str)
{
  GstStructure *s = gst_structure_new_empty ("auth");

  if (auth_str == NULL)
    return s;

  gchar **auth_clip = g_strsplit (auth_str, "&", 1024);
  gchar **param = auth_clip;
  while (*param) {
    gchar **param_clip = g_strsplit (*param, "=", 2);
    gst_structure_set (s, param_clip[0], G_TYPE_STRING, param_clip[1], NULL);
    param++;
    g_strfreev (param_clip);
  }

  g_strfreev (auth_clip);

  return s;
}

gchar *
generate_auth_response (const gchar * username, const gchar * password,
    const gchar * salt, const gchar * opaque, const gchar * challenge)
{
  guint8 digest[16];
  gsize digest_len = 16;
  GChecksum *md5 = g_checksum_new (G_CHECKSUM_MD5);

  g_assert (strlen (challenge) >= 8);

  /* salted = user + salt + password */
  g_checksum_update (md5, (const guint8 *)username, strlen (username));
  g_checksum_update (md5, (const guint8 *)salt, strlen (salt));
  g_checksum_update (md5, (const guint8 *)password, strlen (password));
  g_checksum_get_digest (md5, digest, &digest_len);
  gchar *salted = g_base64_encode (digest, digest_len);

  g_assert (strlen (salted) >= 24);
  g_checksum_reset (md5);

  /* response = salted + opaque + challenge */
  g_checksum_update (md5, (const guint8 *)salted, 24);
  g_checksum_update (md5, (const guint8 *)opaque, strlen (opaque));
  g_checksum_update (md5, (const guint8 *)challenge, 8);
  g_checksum_get_digest (md5, digest, &digest_len);
  gchar *response = g_base64_encode (digest, digest_len);

  g_free (salted);
  g_checksum_free (md5);

  return response;
}

gchar *
get_auth_token (const gchar * server_auth_str,
    const gchar * username, const gchar * password)
{
  GstStructure *s = _map_auth_tokens (server_auth_str);

  const gchar *user = gst_structure_get_string (s, "user");
  const gchar *salt = gst_structure_get_string (s, "salt");
  const gchar *opaque = gst_structure_get_string (s, "opaque");
  /* if no opaque, use challenge */
  if (opaque == NULL)
    opaque = gst_structure_get_string (s, "challenge");

  GST_INFO ("From server: user: %s, salt: %s, opaque: %s", user, salt, opaque);

  /* generate our own challenge */
  guint32 rand_data = g_random_int();
  gchar *challenge = g_base64_encode ((guchar *)&rand_data, sizeof (guint32));

  gchar *response = generate_auth_response (user, password,
      salt, opaque, challenge);

  gchar *ret = g_strdup_printf (
      "?authmod=adobe&user=%s&challenge=%s&response=%s&opaque=%s",
      user, challenge, response, opaque);

  GST_INFO ("Generated token: %s", ret);

  g_free (response);
  g_free (challenge);
  gst_structure_free (s);

  return ret;
}

gboolean
verify_auth (const gchar * app, const gchar * username, const gchar * password,
    const gchar * salt, const gchar * opaque, gchar ** description)
{
  gboolean ret = FALSE;

  gchar **auth_clip = g_strsplit (app, "?", 2);
  const gchar *auth_token = auth_clip[1];

  GstStructure *s = _map_auth_tokens (auth_token);

  const gchar *authmod = gst_structure_get_string (s, "authmod");
  const gchar *user = gst_structure_get_string (s, "user");
  const gchar *challenge = gst_structure_get_string (s, "challenge");
  const gchar *response = gst_structure_get_string (s, "response");

  GST_INFO ("From client: authmod: %s, user: %s, challenge: %s, response: %s",
      authmod, user, challenge, response);

  if (authmod == NULL || user == NULL) {
    *description = g_strdup_printf ("[ AccessManager.Reject ] : "
        "[ code=403 need auth; authmod=adobe ] : ");
    goto done;
  }

  if (challenge == NULL || response == NULL) {
    *description = g_strdup_printf ("[ AccessManager.Reject ] : "
        "[ authmod=adobe ] : "
        "?reason=needauth&user=%s&salt=%s&challenge=%s&opaque=%s",
        user, salt, opaque, opaque);
    goto done;
  }

  gchar *expected_response = generate_auth_response (username, password,
      salt, opaque, challenge);

  if (g_strcmp0 (response, expected_response) == 0) {
    GST_INFO ("Authenticated!");
    ret = TRUE;
  } else {
    *description = g_strdup_printf ("[ AccessManager.Reject ] : "
        "[ f*ck off ] : ");
  }
  g_free (expected_response);

done:
  gst_structure_free (s);
  g_strfreev (auth_clip);

  return ret;
}

struct _GstBufferQueue
{
  GQueue *queue;
  GMutex lock;
  GCond cond;
  gboolean running;
};

GstBufferQueue *
gst_buffer_queue_new ()
{
  GstBufferQueue *queue = g_new0 (GstBufferQueue, 1);
  g_mutex_init (&queue->lock);
  g_cond_init (&queue->cond);
  queue->queue = g_queue_new ();
  queue->running = TRUE;
  return queue;
}

void
gst_buffer_queue_flush (GstBufferQueue * queue)
{
  if (queue->queue == NULL)
    return;
  g_mutex_lock (&queue->lock);
  queue->running = FALSE;
  g_cond_signal (&queue->cond);
  g_queue_free_full (queue->queue, (GDestroyNotify)gst_buffer_unref);
  queue->queue = NULL;
  g_mutex_unlock (&queue->lock);
}

void
gst_buffer_queue_free (GstBufferQueue * queue)
{
  gst_buffer_queue_flush (queue);
  g_cond_clear (&queue->cond);
  g_mutex_clear (&queue->lock);
  g_free (queue);
}

void
gst_buffer_queue_push (GstBufferQueue * queue, GstBuffer * buf)
{
  g_mutex_lock (&queue->lock);
  if (!queue->running) {
    g_mutex_unlock (&queue->lock);
    gst_buffer_unref (buf);
    return;
  }
  g_queue_push_head (queue->queue, buf);
  g_cond_signal (&queue->cond);
  g_mutex_unlock (&queue->lock);
}

GstBuffer *
gst_buffer_queue_pop (GstBufferQueue * queue)
{
  GstBuffer *buf = NULL;
  g_mutex_lock (&queue->lock);
  while (queue->running && g_queue_get_length (queue->queue) == 0)
    g_cond_wait (&queue->cond, &queue->lock);

  if (queue->running)
    buf = g_queue_pop_tail (queue->queue);
  g_mutex_unlock (&queue->lock);
  return buf;
}
