#ifndef __RTMP_HARNESS_H__
#define __RTMP_HARNESS_H__

#include "gstharness.h"
#include "rtmpserver.h"

G_BEGIN_DECLS

typedef enum {
  RTMP_SPEEX,
  RTMP_AAC,
} RTMPAudioCodec;

typedef struct {
  PexRtmpServer * server;
  gchar * application_name;
  gint port;
  gint ssl_port;
  gint chunk_size;

  GstClockTime ts_offset;

  GHashTable * publishers;
  gint publisher_count;

  GHashTable * subscribers;
  gint subscriber_count;

  gboolean reject_publishers;
  gboolean reject_subscribers;

  gint notified_publishers;
  gint notified_subscribers;

  gboolean block_on_publish;
  gboolean block_on_play;

  GMutex lock;
} RTMPHarness;

typedef struct {
  GstHarness * h;
  GstHarness * audio_h;
  GstHarness * video_h;
  GstElement * flvmux;
  gboolean rtmpsink_connected;
  gint id;
  gchar * path;
  GList * push_threads;

  GMutex lock;
  GCond cond;
} Publisher;

typedef struct {
  GstHarness * h;
  GstHarness * audio_h;
  GstHarness * video_h;
  GstElement * rtmpsrc;
  gboolean rtmpsrc_connected;

  gint id;
  gchar * path;

  GValueArray * freq_list;
  GValueArray * participant_list;

  GMutex lock;
  GCond cond;
} Subscriber;

RTMPHarness * rtmp_harness_new (const gchar * application_name);
RTMPHarness * rtmp_harness_new_with_certs (const gchar * application_name,
    const gchar * cert, const gchar * key, const gchar * ca);
RTMPHarness * rtmp_harness_new_with_ports (const gchar * application_name,
    gint port, gint ssl_port);
void rtmp_harness_teardown (RTMPHarness * h);

void rtmp_harness_stop_server (RTMPHarness * h);
void rtmp_harness_start_server (RTMPHarness * h);

void rtmp_harness_lock (RTMPHarness * h);
void rtmp_harness_unlock (RTMPHarness * h);

gboolean rtmp_harness_dialout (RTMPHarness * h_from, gint id_from,
    RTMPHarness * h_to, gint id_to, const gchar * protocol,
    const gchar * host, const gchar * ip);
gboolean rtmp_harness_dialin (RTMPHarness * h_from, gint id_from,
    RTMPHarness * h_to, gint id_to, const gchar * protocol,
    const gchar * host, const gchar * ip);

void rtmp_harness_set_stream_id (RTMPHarness * h, gint stream_id);
void rtmp_harness_set_chunk_size (RTMPHarness * h, gint chunk_size);
void rtmp_harness_set_tcp_syncnt (RTMPHarness * h, gint tcp_syncnt);

gint rtmp_harness_add_bad_client (RTMPHarness * h);
gint rtmp_harness_add_bad_server (RTMPHarness * h, gint port);

void rtmp_harness_set_timestamp_offset (RTMPHarness * h, GstClockTime ts_offset);

/* publisher functions */
gint rtmp_harness_add_publisher (RTMPHarness * h, const gchar * path);
gint rtmp_harness_add_publisher_ssl (RTMPHarness * h, const gchar * path);
void rtmp_harness_remove_publisher (RTMPHarness * h, gint p_id);
void rtmp_harness_wait_for_notified_publishers (RTMPHarness * h, gint publishers);

void rtmp_harness_add_custom_audiosrc (RTMPHarness * h, gint p_id, const gchar * launch_str);
void rtmp_harness_add_audiosrc (RTMPHarness * h, gint p_id, RTMPAudioCodec codec);

void rtmp_harness_add_custom_videosrc (RTMPHarness * h, gint p_id, const gchar * launch_str);
void rtmp_harness_add_videosrc (RTMPHarness * h, gint p_id);

void rtmp_harness_send_audio (RTMPHarness * h, gint p_id, gint cranks, gint pushes);
void rtmp_harness_send_video (RTMPHarness * h, gint p_id, gint cranks, gint pushes);

void rtmp_harness_send_audio_async (RTMPHarness * h, gint p_id, gint cranks, gint pushes);
void rtmp_harness_send_video_async (RTMPHarness * h, gint p_id, gint cranks, gint pushes);

void rtmp_harness_request_intra (RTMPHarness * h, gint p_id);

gboolean rtmp_harness_wait_for_rtmpsink_connection (RTMPHarness * h,
    gint p_id, gboolean connected);
gboolean rtmp_harness_get_rtmpsink_connection (RTMPHarness * h, gint p_id);

/* subscriber functions */
gint rtmp_harness_add_subscriber (RTMPHarness * h, const gchar * path);
gint rtmp_harness_add_subscriber_ssl (RTMPHarness * h, const gchar * path);
void rtmp_harness_remove_subscriber (RTMPHarness * h, gint s_id);
void rtmp_harness_wait_for_notified_subscribers (RTMPHarness * h, gint subscribers);

void rtmp_harness_add_custom_audiosink (RTMPHarness * h, gint s_id, const gchar * launch_str);
void rtmp_harness_add_audiosink (RTMPHarness * h, gint s_id, RTMPAudioCodec codec);

void rtmp_harness_add_videosink (RTMPHarness * h, gint s_id);
void rtmp_harness_add_custom_videosink (RTMPHarness * h, gint s_id, const gchar * launch_str);

void rtmp_harness_recv_audio (RTMPHarness * h, gint s_id, gint pushes);
void rtmp_harness_recv_video (RTMPHarness * h, gint s_id, gint pushes);

gboolean rtmp_harness_verify_recv_audio (RTMPHarness * h, gint s_id, gint p_id);
gboolean rtmp_harness_verify_recv_video (RTMPHarness * h, gint s_id, gint p_id);

gboolean rtmp_harness_wait_for_rtmpsrc_connection (RTMPHarness * h,
    gint s_id, gboolean connected);
void rtmp_harness_restart_rtmpsrc (RTMPHarness * h, gint s_id);

G_END_DECLS

#endif /* __RTMP_HARNESS_H__ */
