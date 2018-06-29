#include "utils.h"

#if defined(HOST_LINUX)
#  include <linux/sockios.h>
#endif
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <arpa/inet.h>
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

int
tcp_set_nonblock (int fd, gboolean enabled)
{
  int flags = fcntl (fd, F_GETFL) & ~O_NONBLOCK;
  if (enabled) {
    flags |= O_NONBLOCK;
  }
  return fcntl (fd, F_SETFL, flags);
}

gint
tcp_connect (const gchar * ip, gint port, gint src_port, gint tcp_syncnt)
{
  int ret;
  int fd;
  struct sockaddr_storage address;

  memset (&address, 0, sizeof (struct sockaddr_storage));

  struct addrinfo hints;
  struct addrinfo *result = NULL;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_STREAM;      /* Stream soc */
  hints.ai_protocol = IPPROTO_TCP;      /* TCP protocol */

  ret = getaddrinfo (ip, NULL, &hints, &result);
  if (ret != 0) {
    GST_WARNING ("getaddrinfo: %s", gai_strerror (ret));
    return INVALID_FD;
  }
  memcpy (&address, result->ai_addr, result->ai_addrlen);
  freeaddrinfo (result);

  fd = socket (address.ss_family, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0) {
    GST_WARNING ("could not create soc: %s", g_strerror (errno));
    return INVALID_FD;
  }

  /* make the connection non-blocking */
  tcp_set_nonblock (fd, TRUE);

  /* set timeout */
  struct timeval tv = { 30, 0 };
  if (setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &tv, sizeof (tv))) {
    GST_WARNING ("Could not set timeout");
  }

  /* Disable packet-accumulation delay (Nagle's algorithm) */
  gint value = 1;
  setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (char *) &value, sizeof (value));
  /* Allow reuse of the local address */
  setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (char *) &value, sizeof (value));

  /* Configure TCP_SYNCNT */
  if (tcp_syncnt >= 0) {
#ifdef TCP_SYNCNT
    value = tcp_syncnt;
    setsockopt (fd, IPPROTO_TCP, TCP_SYNCNT, (char *) &value, sizeof (value));
#endif
  }

  if (src_port) {
    GST_DEBUG ("Connecting to %s:%d from %d", ip, port, src_port);
    if (address.ss_family == AF_INET) {
      struct sockaddr_in sin;
      memset (&sin, 0, sizeof (struct sockaddr_in));
      sin.sin_family = AF_INET;
      sin.sin_port = htons (src_port);
      sin.sin_addr.s_addr = INADDR_ANY;

      if (bind (fd, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        GST_WARNING ("Unable to bind to port %d: %s",
            src_port, strerror (errno));
        close (fd);
        return -1;
      }
    } else {
      struct sockaddr_in6 sin;
      memset (&sin, 0, sizeof (struct sockaddr_in6));
      sin.sin6_family = AF_INET6;
      sin.sin6_port = htons (src_port);
      sin.sin6_addr = in6addr_any;

      if (bind (fd, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        GST_WARNING ("Unable to bind to port %d: %s",
            src_port, strerror (errno));
        close (fd);
        return -1;
      }
    }
  }

  if (address.ss_family == AF_INET) {
    ((struct sockaddr_in *) &address)->sin_port = htons (port);
    ret =
        connect (fd, (struct sockaddr *) &address, sizeof (struct sockaddr_in));
  } else {
    ((struct sockaddr_in6 *) &address)->sin6_port = htons (port);
    ret =
        connect (fd, (struct sockaddr *) &address,
        sizeof (struct sockaddr_in6));
  }

  if (ret != 0 && errno != EINPROGRESS) {
    GST_WARNING ("could not connect on port %d: %s", port, g_strerror (errno));
    close (fd);
    return INVALID_FD;
  }

  return fd;
}

void
tcp_disconnect (gint fd)
{
  shutdown (fd, SHUT_RDWR);
  struct linger linger;
  linger.l_onoff = 1;
  linger.l_linger = 0;
  setsockopt (fd, SOL_SOCKET, SO_LINGER, (char *)&linger, sizeof (linger));
  close (fd);
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

  gint num_ats = count_chars_in_string (the_rest, '@');
  if (num_ats > 0) {
    at_clip = g_strsplit (the_rest, "@", 2);
    const gchar *credentials = at_clip[0];
    the_rest = at_clip[1];
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
  *application_name = g_strndup (&the_rest[strlen (address) + 1],
      strlen (the_rest) - strlen (address) - strlen (*path) - 2);

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
