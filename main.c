#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <gst/gst.h>

#include "rtmpserver.h"


/* defaults */
#define APP_NAME "live"
#define PORT 1935

int
main (int argc, char **argv)
{
  int port;
  const char * application_name;

  if (argc == 1) {
    port = PORT;
    application_name = (char *) APP_NAME;
  }
  if (argc == 2) {
    port = atoi (argv[1]);
    application_name = (char *) APP_NAME;
  }
  if (argc == 3) {
    printf ("ARGV: %s %s\n", argv[1], argv[2]);
    port = atoi (argv[1]);
    application_name = argv[2];
  }
  printf ("Argc: %d, app_name: %s, port: %d\n", argc, application_name, port);

  gst_init (NULL, NULL);

  PexRtmpServer * srv = pex_rtmp_server_new (application_name, port, 0, NULL, NULL);
  if (srv == NULL)
    return 1;

  pex_rtmp_server_start (srv);
  printf ("ready\n");

  /* we will run for 5 minutes */
  g_usleep (G_USEC_PER_SEC * 60 * 5);

  pex_rtmp_server_stop (srv);
  g_object_unref (srv);

  return 0;
}
