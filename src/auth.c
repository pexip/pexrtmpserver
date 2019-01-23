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
#include "auth.h"
#include "rtmp.h"

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

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

static gchar *
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
auth_get_token (const gchar * server_auth_str,
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
auth_verify (const gchar * app, const gchar * username, const gchar * password,
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
