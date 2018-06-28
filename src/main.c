#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <gst/gst.h>

#include "rtmpserver.h"

/*
./gst-launch videotestsrc ! video/x-raw-yuv, width=1280, height=720, pixel-aspect-ratio=1/1 ! \
pexh264enc intra-period=20 bitrate=2000000 level=41 timing-info=1 ! \
video/x-h264, stream-format=byte-stream, alignment=nal ! h264parse ! mux.video \
flvmux name=mux ! rtmpsink location=rtmp://localhost/pexip/youtube -v \
audiotestsrc ! audio/x-raw-int,rate=48000,channels=1 ! pexaacenc !  mux.audio

./rtmpsrv -p 1935 -a pexip -d youtube -u rtmp://a.rtmp.youtube.com/live2/havard.jb8x-02ft-qbcw-9z95

*/

/* defaults */
static gint port = 1935;
static gchar app_name[] = "pexip";
static gchar *dialout_url = NULL;
static gchar *dialout_path = NULL;

static GOptionEntry entries[] = {
  {"port", 'p', 0, G_OPTION_ARG_INT, &port, "Set rtmp listening port to N",
        "N"},
  {"application-name", 'a', 0, G_OPTION_ARG_STRING, &app_name,
        "Set the Application Name", NULL},
  {"dialout-path", 'd', 0, G_OPTION_ARG_STRING, &dialout_path,
        "The rtmp-path to forward to the dialed out address", NULL},
  {"dialout-url", 'u', 0, G_OPTION_ARG_STRING, &dialout_url,
        "The rtmp:// address to dial out to", NULL},
  {NULL, 0, 0, 0, NULL, NULL, NULL},
};

int
main (int argc, char *argv[])
{
  GError *error = NULL;
  GOptionContext *context;

  context = g_option_context_new ("RTMP ");
  g_option_context_add_main_entries (context, entries, NULL);
  if (!g_option_context_parse (context, &argc, &argv, &error)) {
    g_print ("option parsing failed: %s\n", error->message);
    exit (1);
  }

  gst_init (NULL, NULL);

  PexRtmpServer *srv =
      pex_rtmp_server_new (app_name, port, 0, NULL, NULL, NULL, NULL, NULL,
      FALSE, FALSE);
  if (srv == NULL)
    return 1;

  pex_rtmp_server_start (srv);
  printf ("ready...\n");

  if (dialout_path && dialout_url) {
    pex_rtmp_server_dialout (srv, dialout_path, dialout_url, NULL, 0);
    printf ("dialed out from path %s to %s\n", dialout_path, dialout_url);
  }

  /* we will run for 5 minutes */
  g_usleep (G_USEC_PER_SEC * 60 * 5);

  printf ("stopping...");
  pex_rtmp_server_stop (srv);
  g_object_unref (srv);

  return 0;
}
