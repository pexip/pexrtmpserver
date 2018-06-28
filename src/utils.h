#ifndef _UTILS_H_
#define _UTILS_H_

#include <gst/gst.h>
#include <openssl/x509v3.h>

#define INVALID_FD -1

guint32 load_be32 (const void * p);
guint16 load_be16 (const void * p);
guint32 load_be24 (const void * p);
guint32 load_le32 (const void * p);
void set_be24 (void * p, guint32 val);
void set_le32 (void * p, guint32 val);

gint tcp_connect (const gchar * ip, gint port, gint src_port, gint tcp_syncnt);
int tcp_set_nonblock (int fd, gboolean enabled);

gboolean parse_rtmp_url (const gchar * url,
    gchar ** protocol, gint * port, gchar ** ip, gchar ** application_name,
    gchar ** path, gchar ** username, gchar ** password);

int verify_hostname (X509 * cert, const gchar * remote_host);
gboolean file_exists (const gchar * path);
DH * make_dh_params (const gchar * cert_file);

gchar * get_auth_token (const gchar * server_auth_str,
    const gchar * username, const gchar * password);
gboolean verify_auth (const gchar * app, const gchar * username,
    const gchar * password, const gchar * salt, const gchar * opaque,
    gchar ** description);

#endif /* _UTILS_H_ */
