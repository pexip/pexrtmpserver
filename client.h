#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <gst/gst.h>
#include <openssl/ssl.h>
#include "connections.h"

typedef struct _Client Client;

/* 5.4.1.2.1 */
#define DEFAULT_FMT 0

typedef struct
{
  guint8 fmt;
  guint8 type;
  size_t len;
  guint32 timestamp;
  guint32 abs_timestamp;
  guint32 msg_stream_id;
  GByteArray * buf;
} RTMP_Message;

struct _Client
{
  gint fd;
  Connections * connections;
  GObject * server;
  gboolean use_ssl;
  guint msg_stream_id;
  size_t chunk_size;

  guint32 window_size;
  RTMP_Message messages[64];
  GByteArray * send_queue;
  GByteArray * buf;

  gchar * path;
  gchar * dialout_path;

  gboolean playing;             /* Wants to receive the stream? */
  gboolean ready;               /* Wants to receive and seen a keyframe */
  gboolean publisher;           /* Is this a publisher */

  GstStructure * metadata;
  guint32 written_seq;
  guint32 read_seq;

  guint32 bytes_received_since_ack;
  guint32 total_bytes_received;

  int write_queue_size;

  /* crypto */
  SSL_CTX * ssl_ctx;
  SSL * ssl;
};

Client * client_new (gint fd, Connections * connection,
    GObject * server, gboolean use_ssl, gint stream_id, gint chunk_size);
void client_free (Client * client);

size_t client_recv_all (Client * client, void * buf, size_t len);
size_t client_send_all (Client * client, const void * buf, size_t len);

gboolean client_try_to_send (Client * client);
gboolean client_receive (Client * client);
gboolean client_handle_message (Client * client, RTMP_Message * msg);
gboolean client_window_size_reached (Client *client);

gboolean client_add_incoming_ssl (Client * client,
    gchar * cert, gchar * key);

void client_do_connect (Client * client, const gchar * tcUrl,
    const gchar * application_name, const gchar * path);

#endif /* __CLIENT_H__ */

