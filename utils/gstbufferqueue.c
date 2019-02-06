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
#include "gstbufferqueue.h"

struct _GstBufferQueue
{
  GQueue *queue;
  GMutex lock;
  GCond cond;
  gboolean running;
};

GstBufferQueue *
gst_buffer_queue_new ()
{
  GstBufferQueue *queue = g_new0 (GstBufferQueue, 1);
  g_mutex_init (&queue->lock);
  g_cond_init (&queue->cond);
  queue->queue = g_queue_new ();
  queue->running = TRUE;
  return queue;
}

void
gst_buffer_queue_flush (GstBufferQueue * queue)
{
  if (queue->queue == NULL)
    return;
  g_mutex_lock (&queue->lock);
  queue->running = FALSE;
  g_cond_signal (&queue->cond);
  g_queue_free_full (queue->queue, (GDestroyNotify)gst_buffer_unref);
  queue->queue = NULL;
  g_mutex_unlock (&queue->lock);
}

void
gst_buffer_queue_free (GstBufferQueue * queue)
{
  gst_buffer_queue_flush (queue);
  g_cond_clear (&queue->cond);
  g_mutex_clear (&queue->lock);
  g_free (queue);
}

gboolean
gst_buffer_queue_push (GstBufferQueue * queue, GstBuffer * buf)
{
  g_mutex_lock (&queue->lock);
  if (!queue->running) {
    g_mutex_unlock (&queue->lock);
    gst_buffer_unref (buf);
    return FALSE;
  }
  g_queue_push_head (queue->queue, buf);
  g_cond_signal (&queue->cond);
  g_mutex_unlock (&queue->lock);
  return TRUE;
}

GstBuffer *
gst_buffer_queue_pop (GstBufferQueue * queue)
{
  GstBuffer *buf = NULL;
  g_mutex_lock (&queue->lock);
  while (queue->running && g_queue_get_length (queue->queue) == 0)
    g_cond_wait (&queue->cond, &queue->lock);

  if (queue->running)
    buf = g_queue_pop_tail (queue->queue);
  g_mutex_unlock (&queue->lock);
  return buf;
}

GstBuffer *
gst_buffer_queue_try_pop (GstBufferQueue * queue)
{
  GstBuffer *buf = NULL;
  g_mutex_lock (&queue->lock);
  if (queue->running)
    buf = g_queue_pop_tail (queue->queue);
  g_mutex_unlock (&queue->lock);
  return buf;
}

guint
gst_buffer_queue_length (GstBufferQueue * queue)
{
  guint length = 0;
  g_mutex_lock (&queue->lock);
  if (queue->running)
    length = queue->queue->length;
  g_mutex_unlock (&queue->lock);
  return length;
}
