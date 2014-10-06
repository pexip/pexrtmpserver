#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <gst/gst.h>
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
  guint32 endpoint;
  GByteArray * buf;
} RTMP_Message;

struct _Client
{
  Connections * connections;
  GObject * server;
  int fd;
  gboolean playing;             /* Wants to receive the stream? */
  gboolean ready;               /* Wants to receive and seen a keyframe */
  gboolean publisher;           /* Is this a publisher */
  RTMP_Message messages[64];
  gchar * path;
  GByteArray * buf;

  GByteArray * send_queue;
  GstStructure *metadata;
  size_t chunk_len;
  guint32 written_seq;
  guint32 read_seq;

  guint32 window_size;
  guint32 bytes_received_since_ack;
  guint32 total_bytes_received;
};

Client * client_new (gint fd, Connections * connection, GObject * server);
void client_free (Client * client);

gboolean client_try_to_send (Client * client);
gboolean client_receive (Client * client);

#endif /* __CLIENT_H__ */
