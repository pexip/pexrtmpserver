/* PexRTMPServer
 * Copyright (C) 2019 Pexip
 *  @author: Havard Graff <havard@pexip.com>
 *  @author: John-Mark Bell <jmb@pexip.com>
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
#include "ssl.h"

#ifdef G_OS_WIN32
#  include <Ws2ipdef.h>
#else
#  include <arpa/inet.h>
#endif

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

static inline X509 *X509_STORE_CTX_get0_cert (X509_STORE_CTX * ctx)
{
  return ctx->cert;
}

static const unsigned char *
ASN1_STRING_get0_data (ASN1_IA5STRING * candidate)
{
  return (unsigned char *) ASN1_STRING_data (candidate);
}

static int
DH_set0_pqg (DH * dh, BIGNUM * p, BIGNUM * q, BIGNUM * g)
{
  /* If the fields p and g in d are NULL, the corresponding input
   * parameters MUST be non-NULL.  q may remain NULL.
   */
  if ((dh->p == NULL && p == NULL)
      || (dh->g == NULL && g == NULL))
    return 0;

  if (p != NULL) {
    BN_free (dh->p);
    dh->p = p;
  }
  if (q != NULL) {
    BN_free (dh->q);
    dh->q = q;
  }
  if (g != NULL) {
    BN_free (dh->g);
    dh->g = g;
  }

  if (q != NULL) {
    dh->length = BN_num_bits (q);
  }

  return 1;
}

#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000L) */


static int
match_dns_name (const gchar * remote_host, ASN1_IA5STRING * candidate)
{
  const gchar *data = (const gchar *)ASN1_STRING_get0_data (candidate);
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
            memcmp (ASN1_STRING_get0_data (value), &addr, len) == 0) {
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
        int type = EVP_PKEY_type (EVP_PKEY_id (pubkey));
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
          BIGNUM *p = NULL;
          BIGNUM *g = NULL;
          p = gentable[idx].prime (NULL);
          BN_dec2bn (&g, "2");
          if (!DH_set0_pqg (dh, p, NULL, g)) {
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

static int
ssl_verify_callback (int preverify_ok, X509_STORE_CTX * ctx)
{
  SSL *ssl =
      X509_STORE_CTX_get_ex_data (ctx, SSL_get_ex_data_X509_STORE_CTX_idx ());
  gchar *remote_host = SSL_get_app_data (ssl);
  X509 *current_cert = X509_STORE_CTX_get_current_cert (ctx);

  if (preverify_ok == 0 || current_cert == NULL) {
    return preverify_ok;
  }

  X509 *cert = X509_STORE_CTX_get0_cert (ctx);
  /* TODO: Perform OCSP check for current certificate */

  if (current_cert == cert) {
    /* The current certificate is the peer certificate */
    if (remote_host != NULL) {
      preverify_ok = verify_hostname (current_cert, remote_host);
    }
  }

  return preverify_ok;
}

SSL_CTX *
ssl_add_incoming (const gchar * cert_file, const gchar * key_file,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled)
{
  BIO *bio;
  long ssl_options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
      SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_CIPHER_SERVER_PREFERENCE;

  SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_server_method ());

  if (!tls1_enabled)
    ssl_options |= SSL_OP_NO_TLSv1;

  SSL_CTX_set_cipher_list (ssl_ctx, ciphers);
  SSL_CTX_set_options (ssl_ctx, ssl_options);
  if (file_exists (ca_file)) {
    SSL_CTX_load_verify_locations (ssl_ctx, ca_file, NULL);
  } else {
    GST_WARNING ("%s does not exist!", ca_file);
  }
  if (file_exists (ca_dir)) {
    SSL_CTX_load_verify_locations (ssl_ctx, NULL, ca_dir);
  } else {
    GST_WARNING ("%s does not exist!", ca_dir);
  }
  SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_NONE, ssl_verify_callback);
  SSL_CTX_set_mode (ssl_ctx,
      SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  if (file_exists (cert_file) && file_exists (key_file)) {
    if (SSL_CTX_use_certificate_file (ssl_ctx, cert_file,
            SSL_FILETYPE_PEM) <= 0) {
      GST_WARNING ("did not like the certificate: %s", cert_file);
      ssl_print_errors ();
      return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file (ssl_ctx, key_file,
            SSL_FILETYPE_PEM) <= 0) {
      GST_WARNING ("did not like the key: %s", key_file);
      ssl_print_errors ();
      return NULL;
    }

    /* Configure DH parameters */
    bio = BIO_new_file (cert_file, "r");
    if (bio != NULL) {
      DH *dh = PEM_read_bio_DHparams (bio, NULL, NULL, NULL);
      BIO_free (bio);

      if (dh == NULL) {
        dh = make_dh_params (cert_file);
      }

      if (dh != NULL) {
        SSL_CTX_set_tmp_dh (ssl_ctx, dh);
        DH_free (dh);
      }
    }

    /* Configure ECDH parameters */
    bio = BIO_new_file (cert_file, "r");
    if (bio != NULL) {
      EC_KEY *key;
      int nid = NID_X9_62_prime256v1;
      EC_GROUP *group = PEM_read_bio_ECPKParameters (bio, NULL, NULL, NULL);
      BIO_free (bio);

      if (group != NULL) {
        nid = EC_GROUP_get_curve_name (group);
        if (nid == NID_undef) {
          nid = NID_X9_62_prime256v1;
        }

        EC_GROUP_free (group);
      }

      key = EC_KEY_new_by_curve_name (nid);
      if (key != NULL) {
        SSL_CTX_set_tmp_ecdh (ssl_ctx, key);
        EC_KEY_free (key);
      }
    }

    ERR_clear_error ();
  }

  return ssl_ctx;
}

static void
outgoing_ssl_info_callback (const SSL * ssl, int where, int ret)
{
  gchar *remote_host = SSL_get_app_data (ssl);

  if (where & SSL_CB_HANDSHAKE_START) {
    if (remote_host != NULL) {
      if (SSL_set_tlsext_host_name ((SSL *) ssl, remote_host) == 0) {
        ssl_print_errors ();
      }
    }
  }
}

SSL_CTX *
ssl_add_outgoing (const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled)
{
  long ssl_options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

  SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method ());

  if (!tls1_enabled)
    ssl_options |= SSL_OP_NO_TLSv1;

  SSL_CTX_set_cipher_list (ssl_ctx, ciphers);
  SSL_CTX_set_options (ssl_ctx, ssl_options);
  if (file_exists (ca_file)) {
    SSL_CTX_load_verify_locations (ssl_ctx, ca_file, NULL);
  }
  if (file_exists (ca_dir)) {
    SSL_CTX_load_verify_locations (ssl_ctx, NULL, ca_dir);
  }
  SSL_CTX_set_info_callback (ssl_ctx, outgoing_ssl_info_callback);
  SSL_CTX_set_verify (ssl_ctx,
      SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_callback);
  SSL_CTX_set_mode (ssl_ctx,
      SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  return ssl_ctx;
}

void
ssl_print_errors ()
{
  char tmp[4096];
  gint error;
  while ((error = ERR_get_error ()) != 0) {
    memset (tmp, 0, sizeof (tmp));
    ERR_error_string_n (error, tmp, sizeof (tmp) - 1);
    GST_WARNING ("ssl-error: %s", tmp);
  }
}
