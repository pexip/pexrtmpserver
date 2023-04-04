#ifndef __CLIENT_H__
#define __CLIENT_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pexrtmpserver-types.h"

#ifdef G_OS_WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <windows.h>
#endif

#ifdef HAVE_OPENSSL
#  include "utils/ssl.h"
#endif

#include "connections.h"
#include "handshake.h"
#include "utils/gstbufferqueue.h"

typedef struct _Client Client;

typedef gboolean (*NotifyConnectionFunc) (GObject * server, Client * client);

/* 5.4.1.2.1 */
#define DEFAULT_FMT 0

typedef struct
{
  guint8 fmt;
  guint8 type;
  guint len;
  guint32 timestamp;
  guint32 abs_timestamp;
  guint32 msg_stream_id;
  GByteArray *buf;
} RTMPMessage;

typedef struct
{
  guint32 timestamp;
  guint32 msg_stream_id;
  guint8 msg_type_id;
  guint32 abs_timestamp;
  guint msg_len;
} RTMPHeaderData;

typedef enum
{
  CLIENT_TCP_HANDSHAKE_IN_PROGRESS,
  CLIENT_TLS_HANDSHAKE_IN_PROGRESS,
  CLIENT_TLS_HANDSHAKE_WANT_READ,
  CLIENT_TLS_HANDSHAKE_WANT_WRITE,
  CLIENT_CONNECTED,
} ClientConnectionState;

struct _Client
{
  volatile gint ref_count;
  GObject *server;
  PexRtmpClientID id;
  Connections *connections;
  guint msg_stream_id;
  guint chunk_size;
  NotifyConnectionFunc notify_connection;

  gint fd;
  GstPollFD gfd;

  gboolean added_to_fd_table;
  gboolean active;
  gboolean disconnect;
  gboolean not_notified;

  ClientConnectionState state;
  gboolean use_ssl;

  RTMPHeaderData prev_header;
  guint recv_chunk_size;
  guint send_chunk_size;

  guint32 window_size;
  GHashTable *rtmp_messages;
  GByteArray *send_queue;
  GByteArray *buf;

  gchar *protocol;
  gint port;
  gchar *remote_host;

  gchar *path;
  gchar *dialout_path;
  gchar *url;
  gchar *addresses;
  gchar *tcUrl;
  gchar *app;
  gint tcp_syncnt;
  gint src_port;

  /* auth stuff */
  gchar *username;
  gchar *password;
  gchar *auth_token;
  gchar *salt;
  gchar *opaque;

  gboolean playing;             /* Wants to receive the stream? */
  gboolean has_key_frame;       /* Wants to receive and seen a keyframe */
  gboolean publisher;           /* Is this a publisher */
  gboolean has_audio_codec_data; /* Audio Codec-Data has been sent */

  gboolean retry_connection;

  /* metadata stuff */
  GstStructure *metadata;
  gboolean new_metadata;
  gboolean need_metadata;

  guint32 bytes_received_since_ack;
  guint32 total_bytes_received;

  /* Write queue overflow bookkeeping */
  gint last_write_queue_size;
  GTimer *last_queue_overflow;

  PexRtmpHandshake *handshake;
  PexRtmpHandshakeState handshake_state;

#ifdef HAVE_OPENSSL
  SSL_CTX *ssl_ctx;
  SSL *ssl;
#endif /* HAVE_OPENSSL */

  gboolean ssl_write_blocked_on_read;
  gboolean ssl_read_blocked_on_write;
  GByteArray *audio_codec_data;
  GByteArray *video_codec_data;

  gboolean direct;
  GstBufferQueue *flv_queue;
  gboolean write_flv_header;
};

Client * client_new (GObject * server,
    PexRtmpClientID client_id,
    Connections * connections,
    gint stream_id,
    guint chunk_size,
    NotifyConnectionFunc notify_connection);

gboolean client_add_external_connect (Client * client,
    gboolean publisher,
    const gchar * path,
    const gchar * url,
    const gchar * addresses,
    gint src_port,
    gint tcp_syncnt);

gboolean client_add_connection (Client * client, gboolean publisher);

void client_configure_direct (Client * client, const gchar * path, gboolean publisher);

gboolean client_push_flv (Client * client, GstBuffer * buf);
PexRtmpServerStatus client_handle_flv (Client * client);
gboolean client_pull_flv (Client * client, GstBuffer ** buf);
void client_unlock_flv_pull (Client * client);
gboolean client_has_flv_data (Client * client);

PexRtmpServerStatus client_handle_message (Client * client, RTMPMessage * msg);

void client_ref (Client * client);
void client_unref (Client * client);

gboolean client_tcp_connect (Client * client);

void client_get_poll_ctl (Client * client, gboolean * read, gboolean * write);

PexRtmpServerStatus client_send (Client * client);
PexRtmpServerStatus client_receive (Client * client);
gboolean client_window_size_reached (Client *client);

gboolean client_add_incoming_ssl (Client * client,
    const gchar * cert_file, const gchar * key_file,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled);
gboolean client_add_outgoing_ssl (Client * client,
    const gchar * ca_file, const gchar * ca_dir,
    const gchar * ciphers, gboolean tls1_enabled);

#endif /* __CLIENT_H__ */
