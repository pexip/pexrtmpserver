#ifndef __CLIENT_H__
#define __CLIENT_H__

#include <gst/gst.h>
#include "connections.h"

typedef struct _Client Client;

typedef struct
{
  guint8 type;
  size_t len;
  unsigned long timestamp;
  guint32 endpoint;
  GByteArray * buf;
} RTMP_Message;

struct _Client
{
  Connections * connections;
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
};

Client * client_new (gint fd, Connections * connection);
void client_free (Client * client);

gboolean client_try_to_send (Client * client);
gboolean client_receive (Client * client);

#endif /* __CLIENT_H__ */
