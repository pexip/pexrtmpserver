/* PexRTMPServer
 * Copyright (C) 2019 Pexip
 *  @author: Havard Graff <havard@pexip.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */
#ifndef __PEX_RTMP_SERVER_TYPES_H__
#define __PEX_RTMP_SERVER_TYPES_H__

#include <gst/gst.h>

#ifdef G_OS_WIN32
#  ifdef PEX_RTMPSERVER_EXPORTS
#    define PEX_RTMPSERVER_EXPORT __declspec(dllexport)
#  else
#    define PEX_RTMPSERVER_EXPORT __declspec(dllimport) extern
#  endif
#else
#  define PEX_RTMPSERVER_EXPORT extern
#endif

typedef gint PexRtmpClientID;

typedef enum
{
  PEX_RTMP_SERVER_STATUS_OK = 0,
  PEX_RTMP_SERVER_STATUS_BAD,
  PEX_RTMP_SERVER_STATUS_FD_ERROR,
  PEX_RTMP_SERVER_STATUS_SEND_FAILED,
  PEX_RTMP_SERVER_STATUS_RECV_EOF,
  PEX_RTMP_SERVER_STATUS_RECV_FAILED,
  PEX_RTMP_SERVER_STATUS_SSL_NEW_FAILED,
  PEX_RTMP_SERVER_STATUS_SSL_WRITE_FAILED,
  PEX_RTMP_SERVER_STATUS_SSL_READ_FAILED,
  PEX_RTMP_SERVER_STATUS_SSL_ACCEPT_FAILED,
  PEX_RTMP_SERVER_STATUS_TCP_HANDSHAKE_FAILED,
  PEX_RTMP_SERVER_STATUS_INVALID_MSG_LEN,
  PEX_RTMP_SERVER_STATUS_MULTIPLE_PUBLISHERS,
  PEX_RTMP_SERVER_STATUS_ERROR,
  PEX_RTMP_SERVER_STATUS_AUTH_REJECTED,
  PEX_RTMP_SERVER_STATUS_NEED_AUTH,
  PEX_RTMP_SERVER_STATUS_INVALID_FCPUBLISH,
  PEX_RTMP_SERVER_STATUS_INVALID_PUBLISH,
  PEX_RTMP_SERVER_STATUS_PUBLISH_REJECTED,
  PEX_RTMP_SERVER_STATUS_PLAY_REJECTED,
  PEX_RTMP_SERVER_STATUS_INVALID_PLAY,
  PEX_RTMP_SERVER_STATUS_INVALID_PLAY2,
  PEX_RTMP_SERVER_STATUS_INVALID_INVOKE,
  PEX_RTMP_SERVER_STATUS_INVALID_MSG,
  PEX_RTMP_SERVER_STATUS_NOT_SUPPORTED,
  PEX_RTMP_SERVER_STATUS_HANDSHAKE_PROCESS_FAILED,
  PEX_RTMP_SERVER_STATUS_HANDSHAKE_VERIFY_FAILED,
  PEX_RTMP_SERVER_STATUS_HANDSHAKE_PLAINTEXT_FAILED,
  PEX_RTMP_SERVER_STATUS_TCP_CONNECT_FAILED,
  PEX_RTMP_SERVER_STATUS_SSL_CONNECT_FAILED,
  PEX_RTMP_SERVER_STATUS_PARSE_FAILED,
} PexRtmpServerStatus;

#endif /* __PEX_RTMP_SERVER_TYPES_H__ */
