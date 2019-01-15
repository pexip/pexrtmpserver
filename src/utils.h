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
void set_be32 (void * p, guint32 val);

guint parse_flv_header (const guint8 * data);
guint parse_flv_tag (const guint8 * data, guint size,
    guint8 * packet_type, guint * payload_size, guint * timestamp);
GstBuffer * generate_flv_header ();
GstBuffer * generate_flv_tag (const guint8 * data,
    gsize size, guint8 id, guint32 timestamp);

/*
gboolean parse_rtmp_url (const gchar * url,
    gchar ** protocol, gint * port, gchar ** ip, gchar ** application_name,
    gchar ** path, gchar ** username, gchar ** password);

gint tcp_connect (const gchar * ip, gint port, gint src_port, gint tcp_syncnt);
gint tcp_listen (gint port);
void tcp_disconnect (gint fd);
*/
gint tcp_accept (gint listen_fd);
void tcp_set_nonblock (int fd, gboolean enabled);


int verify_hostname (X509 * cert, const gchar * remote_host);
gboolean file_exists (const gchar * path);
DH * make_dh_params (const gchar * cert_file);

gchar * get_auth_token (const gchar * server_auth_str,
    const gchar * username, const gchar * password);
gboolean verify_auth (const gchar * app, const gchar * username,
    const gchar * password, const gchar * salt, const gchar * opaque,
    gchar ** description);

typedef struct _GstBufferQueue GstBufferQueue;

GstBufferQueue * gst_buffer_queue_new ();
void gst_buffer_queue_free (GstBufferQueue * queue);
void gst_buffer_queue_flush (GstBufferQueue * queue);
void gst_buffer_queue_push (GstBufferQueue * queue, GstBuffer * buf);
GstBuffer * gst_buffer_queue_pop (GstBufferQueue * queue);

#endif /* _UTILS_H_ */
