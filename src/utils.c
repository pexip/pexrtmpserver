#include "utils.h"

/*
 * Used to do unaligned loads on archs that don't support them. GCC can mostly
 * optimize these away.
 */
guint32
load_be32 (const void *p)
{
  guint32 val = *((guint32 *) p);
  return GUINT32_FROM_BE (val);
}

guint16
load_be16 (const void *p)
{
  guint16 val = *((guint16 *) p);
  return GUINT16_FROM_BE (val);
}

guint32
load_le32 (const void *p)
{
  guint32 val = *((guint32 *) p);
  return val;
}

guint32
load_be24 (const void *p)
{
  const guint8 *data = (const guint8 *) p;
  return data[2] | ((guint32) data[1] << 8) | ((guint32) data[0] << 16);
}

void
set_be24 (void *p, guint32 val)
{
  guint8 *data = (guint8 *) p;
  data[0] = val >> 16;
  data[1] = val >> 8;
  data[2] = val;
}

void
set_le32 (void *p, guint32 val)
{
  guint8 *data = (guint8 *) p;
  data[0] = val;
  data[1] = val >> 8;
  data[2] = val >> 16;
  data[3] = val >> 24;
}
