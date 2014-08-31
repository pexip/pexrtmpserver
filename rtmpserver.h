#ifndef __RTMP_SERVER_H__
#define __RTMP_SERVER_H__

typedef struct _RTMPServer RTMPServer;

RTMPServer * rtmp_server_new (const char * application_name, int port);
void rtmp_server_free (RTMPServer * srv);

void rtmp_server_do_poll (RTMPServer * srv);

#endif /* __RTMP_SERVER_H__ */
