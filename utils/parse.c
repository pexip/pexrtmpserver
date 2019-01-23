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
#include "parse.h"

GST_DEBUG_CATEGORY_EXTERN (pex_rtmp_server_debug);
#define GST_CAT_DEFAULT pex_rtmp_server_debug

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
