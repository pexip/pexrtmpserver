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
#include "handshake.h"
#include <string.h>

#define TOTAL_HANDSHAKE_LENGTH 1 + HANDSHAKE_LENGTH + HANDSHAKE_LENGTH
#define HASH_LENGTH 16 + 20
#define KEYS_LENGTH 128
GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

const guint8 SERVER_KEY[] = {
  0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20, 0x41, 0x64, 0x6f, 0x62,
  0x65, 0x20, 0x46, 0x6c, 0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69,
  0x61, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x30, 0x30, 0x31,
  0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8, 0x2e, 0x00, 0xd0, 0xd1,
  0x02, 0x9e, 0x7e, 0x57, 0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
  0x93, 0xb8, 0xe6, 0x36, 0xcf, 0xeb, 0x31, 0xae
};

const guint8 FLASHPLAYER_KEY[] = {
  0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20, 0x41, 0x64, 0x6F, 0x62,
  0x65, 0x20, 0x46, 0x6C, 0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79,
  0x65, 0x72, 0x20, 0x30, 0x30, 0x31, 0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68,
  0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57, 0x6E, 0xEC,
  0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB,
  0x31, 0xAE
};

const guint8 handshake_header[] = {
  0, 0, 0, 0, 1, 2, 3, 4
};

struct _PexRtmpHandshake
{
  guint8 hash[HASH_LENGTH];
  guint8 keys[KEYS_LENGTH];
  guint8 handshake_buffer[TOTAL_HANDSHAKE_LENGTH];
  guint8 *first_half;
  guint8 *second_half;
};

/*
static void
print_data (const guint8 * data, guint len)
{
  for (guint i = 0; i < len; i++)
    GST_INFO ("0x%x ", data[i]);
}
*/

static int
_get_scheme (PexRtmpHandshake * hs, const guint8 data[HANDSHAKE_LENGTH])
{
  GHmac *hmac;
  gint digest_offset = 0;
  gsize hash_len = 32;

  for (int i = 8; i < 12; i++)
    digest_offset += data[i];
  digest_offset %= 728;
  digest_offset += 12;

  hmac = g_hmac_new (G_CHECKSUM_SHA256, &FLASHPLAYER_KEY[0], 30);
  g_hmac_update (hmac, &data[0], digest_offset);
  g_hmac_update (hmac, &data[digest_offset + 32],
      HANDSHAKE_LENGTH - digest_offset - 32);
  g_hmac_get_digest (hmac, &hs->hash[0], &hash_len);
  g_hmac_unref (hmac);

  g_assert_cmpint (hash_len, ==, 32);
  if (memcmp (&hs->hash[0], &data[digest_offset], hash_len) == 0) {
    GST_INFO ("Identified scheme 0");
    return 0;
  }

  digest_offset = 0;
  for (int i = 772; i < 776; i++)
    digest_offset += data[i];
  digest_offset %= 728;
  digest_offset += 776;

  hmac = g_hmac_new (G_CHECKSUM_SHA256, &FLASHPLAYER_KEY[0], 30);
  g_hmac_update (hmac, &data[0], digest_offset);
  g_hmac_update (hmac, &data[digest_offset + 32],
      HANDSHAKE_LENGTH - digest_offset - 32);
  g_hmac_get_digest (hmac, &hs->hash[0], &hash_len);
  g_hmac_unref (hmac);
  g_assert_cmpint (hash_len, ==, 32);

  if (memcmp (&hs->hash[0], &data[digest_offset], hash_len) == 0) {
    GST_INFO ("Identified scheme 1");
    return 1;
  }

  GST_INFO ("Can't parse Handshake, assuming scheme 0");
  return 0;
}

gboolean
pex_rtmp_handshake_process (PexRtmpHandshake * hs, const guint8 * org_data,
    gint len)
{
  GHmac *hmac;
  gsize hash_len = 32;

  if (len != HANDSHAKE_LENGTH + 1) {
    GST_INFO ("Invalid handshake lenght");
    return FALSE;
  }

  guint8 type = org_data[0];
  if (type != 3) {
    GST_INFO ("Invalid handshake type %d", type);
    return FALSE;
  }

  hs->handshake_buffer[0] = type;
  const guint8 *data = &org_data[1];

  /* get the scheme of things */
  gint scheme = _get_scheme (hs, &data[0]);

  /* FIRST BIT */

  /* inital handshake setup */
  memcpy (&hs->first_half[0], handshake_header, sizeof (handshake_header));
  for (guint i = sizeof (handshake_header); i < HANDSHAKE_LENGTH; i++)
    hs->first_half[i] = 1;      /* FIXME: random */

  /* find the keys offset */
  gint keys_offset = 0;
  if (scheme == 1) {
    for (gint i = 768; i < 772; i++)
      keys_offset += hs->first_half[i];
    keys_offset %= 632;
    keys_offset += 8;
  } else {
    for (gint i = 1532; i < 1536; i++)
      keys_offset += hs->first_half[i];
    keys_offset %= 632;
    keys_offset += 772;
  }

  /* copy in the keys */
  memcpy (&hs->first_half[keys_offset], &hs->keys[0], KEYS_LENGTH);

  /* find the hash offset */
  gint hash_offset = 0;
  if (scheme == 1) {
    for (gint i = 772; i < 776; i++)
      hash_offset += hs->first_half[i];
    hash_offset %= 728;
    hash_offset += 776;
  } else {
    for (gint i = 8; i < 12; i++)
      hash_offset += hs->first_half[i];
    hash_offset %= 728;
    hash_offset += 12;
  }

  hmac = g_hmac_new (G_CHECKSUM_SHA256, &SERVER_KEY[0], 36);
  g_hmac_update (hmac, &hs->first_half[0], hash_offset);
  g_hmac_update (hmac, &hs->first_half[hash_offset + 32],
      HANDSHAKE_LENGTH - hash_offset - 32);
  g_hmac_get_digest (hmac, &hs->hash[0], &hash_len);
  g_hmac_unref (hmac);
  g_assert_cmpint (hash_len, ==, 32);

  /* copy in the hash */
  memcpy (&hs->first_half[hash_offset], &hs->hash[0], hash_len);

  /* find the challenge key offset */
  gint key_challenge_offset = 0;
  if (scheme == 1) {
    for (gint i = 772; i < 776; i++)
      key_challenge_offset += data[i];
    key_challenge_offset %= 728;
    key_challenge_offset += 776;
  } else {
    for (gint i = 8; i < 12; i++)
      key_challenge_offset += data[i];
    key_challenge_offset %= 728;
    key_challenge_offset += 12;
  }

  /* hash it */
  hmac = g_hmac_new (G_CHECKSUM_SHA256, &SERVER_KEY[0], 68);
  g_hmac_update (hmac, &data[key_challenge_offset], 32);
  g_hmac_get_digest (hmac, &hs->hash[0], &hash_len);
  g_hmac_unref (hmac);
  g_assert_cmpint (hash_len, ==, 32);

  /* SECOND BIT */

  /* random data */
  for (guint i = 0; i < HANDSHAKE_LENGTH - 32; i++)
    hs->second_half[i] = 1;     /* FIXME: random */

  /* hash it */
  hmac = g_hmac_new (G_CHECKSUM_SHA256, &hs->hash[0], 32);
  g_hmac_update (hmac, &hs->second_half[0], HANDSHAKE_LENGTH - 32);
  g_hmac_get_digest (hmac, &hs->hash[0], &hash_len);
  g_hmac_unref (hmac);
  g_assert_cmpint (hash_len, ==, 32);

  /* copy that hash in last */
  memcpy (&hs->second_half[HANDSHAKE_LENGTH - 32], &hs->hash[0], hash_len);

  return TRUE;
}

static void
generate_key_pair (guint8 keys[KEYS_LENGTH])
{
  for (int i = 0; i < KEYS_LENGTH; i++) {
    keys[i] = 1;                //FIXME: rand it
  }
}

PexRtmpHandshake *
pex_rtmp_handshake_new ()
{
  PexRtmpHandshake *hs = g_new0 (PexRtmpHandshake, 1);

  hs->first_half = &hs->handshake_buffer[1];
  hs->second_half = &hs->handshake_buffer[1 + HANDSHAKE_LENGTH];

  /* generate a key */
  generate_key_pair (&hs->keys[0]);

  return hs;
}

void
pex_rtmp_handshake_free (PexRtmpHandshake * hs)
{
  g_free (hs);
}

guint8 *
pex_rtmp_handshake_get_buffer (PexRtmpHandshake * hs)
{
  return &hs->handshake_buffer[0];
}

guint
pex_rtmp_handshake_get_length (PexRtmpHandshake * hs)
{
  (void) hs;
  return TOTAL_HANDSHAKE_LENGTH;
}

gboolean
pex_rtmp_handshake_verify_reply (PexRtmpHandshake * hs,
    guint8 reply[HANDSHAKE_LENGTH])
{
  /* the client should send back the same thing we sent it after 4 bytes
     timestamp and 4 bytes server version */
  if (memcmp (hs->first_half + 8, reply + 8, HANDSHAKE_LENGTH - 8) != 0) {
    GST_INFO ("Warning handshake verify failed. Acting like it was correct");
  }
  return TRUE;
}
