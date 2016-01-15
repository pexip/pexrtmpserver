#ifndef __utils_h
#define __utils_h

#include <gst/gst.h>

guint32 load_be32 (const void * p);
guint16 load_be16 (const void * p);
guint32 load_be24 (const void * p);
guint32 load_le32 (const void * p);
void set_be24 (void * p, guint32 val);
void set_le32 (void * p, guint32 val);

#endif
