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
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#  include <openssl/param_build.h>
#  include <openssl/params.h>
#endif

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

static const DH *
EVP_PKEY_get0_DH (const EVP_PKEY *pkey)
{
  return pkey->pkey.dh;
}

static const EC_KEY *
EVP_PKEY_get0_EC_KEY (const EVP_PKEY *pkey)
{
  return pkey->pkey.ec;
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

#define BN_get_rfc3526_prime_2048 get_rfc3526_prime_2048
#define BN_get_rfc3526_prime_3072 get_rfc3526_prime_3072
#define BN_get_rfc3526_prime_4096 get_rfc3526_prime_4096
#define BN_get_rfc3526_prime_6144 get_rfc3526_prime_6144
#define BN_get_rfc3526_prime_8192 get_rfc3526_prime_8192
#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000L) */

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
static EVP_PKEY *
d2i_KeyParams(int type, EVP_PKEY **a, const unsigned char **pp, long length)
{
  EVP_PKEY *pkey = NULL;

  if (type != EVP_PKEY_DH && type != EVP_PKEY_EC) {
    return NULL;
  }

  if (a == NULL || *a == NULL) {
    pkey = EVP_PKEY_new ();
  } else {
    pkey = *a;
  }

  if (type == EVP_PKEY_DH) {
    DH *dh = d2i_DHparams (NULL, pp, length);
    if (dh == NULL) {
      goto failed;
    }
    if (EVP_PKEY_set1_DH (pkey, dh) != 1) {
      DH_free (dh);
      goto failed;
    }
    DH_free (dh);
  } else {
    EC_KEY *key = NULL;
    EC_GROUP *group = d2i_ECPKParameters (NULL, pp, length);
    if (group == NULL) {
      goto failed;
    }
    key = EC_KEY_new ();
    if (key == NULL) {
      EC_GROUP_free (group);
      goto failed;
    }
    if (EC_KEY_set_group (key, group) != 1) {
      EC_KEY_free (key);
      EC_GROUP_free (group);
      goto failed;
    }
    if (EVP_PKEY_set1_EC_KEY (pkey, key) != 1) {
      EC_KEY_free (key);
      EC_GROUP_free (group);
      goto failed;
    }
    EC_KEY_free (key);
    EC_GROUP_free (group);
  }

  if (a != NULL) {
    *a = pkey;
  }

  return pkey;

failed:
  if (a == NULL || *a == NULL) {
    EVP_PKEY_free (pkey);
  }
  return NULL;
}

static int
SSL_CTX_set0_tmp_dh_pkey (SSL_CTX *ctx, EVP_PKEY *dhpkey)
{
  const DH *dh = EVP_PKEY_get0_DH (dhpkey);
  if (dh != NULL) {
    SSL_CTX_set_tmp_dh (ctx, dh);
  }
  EVP_PKEY_free (dhpkey);
  return 1;
}
#endif /* (OPENSSL_VERSION_NUMBER < 0x30000000L) */

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

EVP_PKEY *
make_dh_params (const gchar * cert_file)
{
  EVP_PKEY *pkey = NULL;
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
          2048, BN_get_rfc3526_prime_2048}, {
          3072, BN_get_rfc3526_prime_3072}, {
          4096, BN_get_rfc3526_prime_4096}, {
          6144, BN_get_rfc3526_prime_6144}, {
          8192, BN_get_rfc3526_prime_8192}
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

        do {
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
          DH *dh = DH_new ();
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
	  if (dh != NULL) {
            pkey = EVP_PKEY_new ();
            if (pkey != NULL) {
              if (!EVP_PKEY_set1_DH (pkey, dh)) {
                EVP_PKEY_free (pkey);
                DH_free (dh);
                pkey = NULL;
              }
            }
            DH_free (dh);
          }
#else
          OSSL_PARAM_BLD *bld = NULL;
          OSSL_PARAM *params = NULL;
          EVP_PKEY_CTX *ctx = NULL;

          bld = OSSL_PARAM_BLD_new();
          if (bld != NULL) {
            BIGNUM *p = NULL;
            BIGNUM *g = NULL;
            p = gentable[idx].prime (NULL);
            BN_dec2bn (&g, "2");

            if (OSSL_PARAM_BLD_push_BN (bld, "g", g) &&
                OSSL_PARAM_BLD_push_BN (bld, "p", p)) {
              params = OSSL_PARAM_BLD_to_param (bld);
              if (params != NULL) {
                ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_DH, NULL);
                if (ctx != NULL) {
                  if (EVP_PKEY_fromdata_init (ctx) == 1) {
                    if (EVP_PKEY_fromdata (ctx, &pkey, EVP_PKEY_KEY_PARAMETERS,
                        params) == 0) {
                      pkey = NULL;
                    }
                  }
                  EVP_PKEY_CTX_free (ctx);
                }
                OSSL_PARAM_free (params);
              }
            }
            BN_free (g);
            BN_free (p);
            OSSL_PARAM_BLD_free (bld);
          }
#endif
        } while (0);
      }
      X509_free (cert);
    }
  }

  return pkey;
}

static EVP_PKEY *
pkey_parameters_from_file(const gchar * filename, int type)
{
  const char *tname;
  BIO *bio;
  EVP_PKEY *pkey = NULL;

  if (type == EVP_PKEY_DH) {
    tname = PEM_STRING_DHPARAMS;
  } else if (type == EVP_PKEY_EC) {
    tname = PEM_STRING_ECPARAMETERS;
  } else {
    return NULL;
  }

  bio = BIO_new_file (filename, "r");
  if (bio != NULL) {
    unsigned char *data = NULL;
    char *name = NULL;
    long length = 0;
    int rc;

    rc = PEM_bytes_read_bio (&data, &length, &name, tname, bio, NULL, NULL);
    if (rc == 1) {
      const unsigned char *p = data;
      pkey = d2i_KeyParams (type, NULL, &p, length);
      free (name);
      free (data);
    }
    BIO_free (bio);
  }

  return pkey;
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
  int seclevel = 0;
  int min_version = TLS1_VERSION;
  long ssl_options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
      SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE |
      SSL_OP_CIPHER_SERVER_PREFERENCE;

  SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_server_method ());

  if (!tls1_enabled) {
    seclevel = 2;
    min_version = TLS1_2_VERSION;
    ssl_options |= SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  SSL_CTX_set_security_level (ssl_ctx, seclevel);
  SSL_CTX_set_min_proto_version (ssl_ctx, min_version);
#endif
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
    EVP_PKEY *params;

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
    params = pkey_parameters_from_file (cert_file, EVP_PKEY_DH);
    if (params == NULL) {
      params = make_dh_params (cert_file);
    }

    if (params != NULL) {
      if (SSL_CTX_set0_tmp_dh_pkey (ssl_ctx, params) != 1) {
        EVP_PKEY_free (params);
      }
    }

    /* Configure ECDH parameters */
    params = pkey_parameters_from_file (cert_file, EVP_PKEY_EC);
    if (params != NULL) {
      int nid = NID_undef;
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
      const EC_KEY *key = EVP_PKEY_get0_EC_KEY (params);
      if (key != NULL) {
        const EC_GROUP *group = EC_KEY_get0_group (key);
        nid = EC_GROUP_get_curve_name (group);
      }
#else
      char *group;
      size_t len;

      if (EVP_PKEY_get_group_name (params, NULL, 0, &len) == 1) {
        group = OPENSSL_malloc (len + 1);
        if (group != NULL) {
          if (EVP_PKEY_get_group_name (params, group, len + 1, &len) == 1) {
            nid = OBJ_sn2nid (group);
          }
          OPENSSL_free (group);
        }
      }
#endif

      if (nid != NID_undef) {
        SSL_CTX_set1_curves (ssl_ctx, &nid, 1);
      }

      EVP_PKEY_free (params);
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_CTX_set_ecdh_auto (ssl_ctx, 1);
#endif

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
  int seclevel = 0;
  int min_version = TLS1_VERSION;
  long ssl_options = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;

  SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method ());

  if (!tls1_enabled) {
    seclevel = 2;
    min_version = TLS1_2_VERSION;
    ssl_options |= SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
  }

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  SSL_CTX_set_security_level (ssl_ctx, seclevel);
  SSL_CTX_set_min_proto_version (ssl_ctx, min_version);
#endif
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
