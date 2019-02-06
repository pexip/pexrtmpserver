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
#ifndef __GST_BUFFFER_QUEUE_H__
#define __GST_BUFFFER_QUEUE_H__

#include <gst/gst.h>

typedef struct _GstBufferQueue GstBufferQueue;

GstBufferQueue * gst_buffer_queue_new ();
void gst_buffer_queue_free (GstBufferQueue * queue);
void gst_buffer_queue_flush (GstBufferQueue * queue);
gboolean gst_buffer_queue_push (GstBufferQueue * queue, GstBuffer * buf);
GstBuffer * gst_buffer_queue_pop (GstBufferQueue * queue);
GstBuffer * gst_buffer_queue_try_pop (GstBufferQueue * queue);

#endif /* __GST_BUFFFER_QUEUE_H__ */
