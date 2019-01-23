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
#ifndef __SSL_H__
#define __SSL_H__

#include <gst/gst.h>
#ifdef G_OS_WIN32
#  include <winsock2.h>
#endif
#include <openssl/ssl.h>

void ssl_print_errors ();

SSL_CTX * ssl_add_outgoing (const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled);
SSL_CTX * ssl_add_incoming (const gchar * cert_file, const gchar * key_file,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled);

#endif /* __SSL_H__ */
