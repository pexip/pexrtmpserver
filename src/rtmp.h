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
#ifndef __RTMP_H__
#define __RTMP_H__

#include <gst/gst.h>

#define DEFAULT_CHUNK_SIZE 128      /* 5.4.1 */
#define DEFAULT_WINDOW_SIZE 128000

#define HANDSHAKE_PLAINTEXT 0x03
#define HANDSHAKE_CRYPTO    0x06

#define MSG_SET_CHUNK       0x01
#define MSG_ACK             0x03
#define MSG_USER_CONTROL    0x04
#define MSG_WINDOW_ACK_SIZE 0x05
#define MSG_SET_PEER_BW     0x06
#define MSG_AUDIO           0x08
#define MSG_VIDEO           0x09
#define MSG_DATA            0x0F    /* AMF0 */
#define MSG_INVOKE3         0x11    /* AMF3 */
#define MSG_NOTIFY          0x12
//#define MSG_OBJECT          0x13
#define MSG_INVOKE          0x14    /* AMF0 */
#define MSG_FLASH_VIDEO     0x16
//#define MSG_DATA3           0x18    /* AMF3 */

#define CONTROL_CLEAR_STREAM    0x00
/*
#define CONTROL_CLEAR_BUFFER    0x01
#define CONTROL_STREAM_DRY      0x02
#define CONTROL_BUFFER_TIME     0x03
#define CONTROL_RESET_STREAM    0x04
#define CONTROL_PING            0x06
#define CONTROL_REQUEST_VERIFY  0x1a
#define CONTROL_RESPOND_VERIFY  0x1b
#define CONTROL_BUFFER_EMPTY    0x1f
#define CONTROL_BUFFER_READY    0x20
*/

#define MSG_STREAM_ID_CONTROL 0

#define CHUNK_STREAM_ID_CONTROL 2
#define CHUNK_STREAM_ID_RESULT  3
#define CHUNK_STREAM_ID_STREAM  4

#define FLV_KEY_FRAME   0x01
#define FLV_INTER_FRAME 0x02

#define SUPPORT_SND_AAC   0x0400
#define SUPPORT_SND_SPEEX 0x0800
#define SUPPORT_VID_H264  0x0080

/* Chunk Message Header sizes based on "fmt" sizes, see 5.3.1.2 in spec */
static const gint CHUNK_MSG_HEADER_LENGTH[] = { 12, 8, 4, 1 };
static const guint32 EXT_TIMESTAMP_LIMIT = 0xffffff;

#endif /* __RTMP_H__ */
