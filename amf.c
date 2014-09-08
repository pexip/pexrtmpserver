#include "amf.h"
#include "utils.h"
#include <string.h>
#include <arpa/inet.h>

AmfEnc *
amf_enc_new ()
{
  AmfEnc * enc = g_new0 (AmfEnc, 1);
  enc->buf = g_byte_array_new ();
  return enc;
}

void
amf_enc_free (AmfEnc * enc)
{
  g_byte_array_free (enc->buf, TRUE);
  g_free (enc);
}

static void
amf_enc_add (AmfEnc * enc, const guint8 * data, guint len)
{
  enc->buf = g_byte_array_append (enc->buf, data, len);
}

static void
amf_enc_add_char (AmfEnc * enc, char c)
{
  amf_enc_add (enc, (guint8 *)&c, 1);
}

void
amf_enc_add_short (AmfEnc * enc, guint16 s)
{
  amf_enc_add (enc, (guint8 *)&s, 2);
}

void
amf_enc_add_int (AmfEnc * enc, guint32 i)
{
  amf_enc_add (enc, (guint8 *)&i, 4);
}

void
amf_enc_write_key (AmfEnc * enc, const gchar * str)
{
  guint len = strlen (str);
  guint16 str_len = htons (len);
  amf_enc_add_short (enc, str_len);
  amf_enc_add (enc, (const guint8 *)str, len);
}

void
amf_enc_write_string (AmfEnc * enc, const gchar * str)
{
  amf_enc_add_char (enc, AMF0_STRING);
  amf_enc_write_key (enc, str);
}

static void
amf_enc_write_int (AmfEnc * enc, int i)
{
  amf_enc_write_double(enc, (double) i);
}

void
amf_enc_write_double (AmfEnc * enc, double n)
{
  amf_enc_add_char (enc, AMF0_NUMBER);
  uint64_t encoded = 0;
#if defined(__i386__) || defined(__x86_64__)
  /* Flash uses same floating point format as x86 */
  memcpy (&encoded, &n, 8);
#endif
  uint32_t val = htonl (encoded >> 32);
  amf_enc_add_int (enc, val);
  val = htonl (encoded);
  amf_enc_add_int (enc, val);
}

void
amf_enc_write_bool (AmfEnc * enc, gboolean b)
{
  amf_enc_add_char (enc, AMF0_BOOLEAN);
  amf_enc_add_char (enc, b);
}

static void
amf_enc_write_structure (AmfEnc * enc, const GstStructure * s)
{
  gint len = gst_structure_n_fields (s);
  for (int i = 0; i < len; i++) {
    const gchar * key = gst_structure_nth_field_name (s, i);
    const GValue * value = gst_structure_get_value (s, key);
    amf_enc_write_key (enc, key);
    amf_enc_write_value (enc, value);
  }
  amf_enc_write_key (enc, "");
}

void
amf_enc_write_object (AmfEnc * enc, const GstStructure * object)
{
  g_assert (gst_structure_has_name (object, "object"));
  amf_enc_add_char (enc, AMF0_OBJECT);
  amf_enc_write_structure (enc, object);
  amf_enc_add_char (enc, AMF0_OBJECT_END);
}

void
amf_enc_write_ecma (AmfEnc * enc, const GstStructure * object)
{
  amf_enc_add_char (enc, AMF0_ECMA_ARRAY);
  amf_enc_add_int (enc, htonl (gst_structure_n_fields (object) + 1));
  amf_enc_write_structure (enc, object);
  amf_enc_add_char (enc, AMF0_OBJECT_END);
}

void
amf_enc_write_null (AmfEnc * enc)
{
  amf_enc_add_char (enc, AMF0_NULL);
}

void
amf_enc_write_value (AmfEnc * enc, const GValue * value)
{
  switch (G_VALUE_TYPE (value)) {
    case G_TYPE_STRING:
      amf_enc_write_string (enc, g_value_get_string (value));
      break;
    case G_TYPE_DOUBLE:
      amf_enc_write_double (enc, g_value_get_double (value));
      break;
    case G_TYPE_INT:
      amf_enc_write_int (enc, g_value_get_int (value));
      break;
    case G_TYPE_BOOLEAN:
      amf_enc_write_bool (enc, g_value_get_boolean (value));
      break;
    case G_TYPE_INVALID:
    case G_TYPE_NONE:
      amf_enc_write_null (enc);
      break;
    default:
      if (G_VALUE_TYPE (value) == GST_TYPE_STRUCTURE)
        amf_enc_write_object (enc, gst_value_get_structure (value));
      else
        g_warning ("unknown type %u", (guint)G_VALUE_TYPE (value));
      break;
  }
}

AmfDec *
amf_dec_new (GByteArray * buf, guint pos)
{
  AmfDec * dec = g_new0 (AmfDec, 1);
  dec->buf = buf;
  dec->pos = pos;
  return dec;
}

void
amf_dec_free (AmfDec * dec)
{
  g_free (dec);
}

static guint8
amf_dec_peek (const AmfDec * dec)
{
  if (dec->pos >= dec->buf->len) {
    g_warning ("%s: Not enough data", __FUNCTION__);
  }
  return dec->buf->data[dec->pos];
}

static guint8
amf_dec_get_byte (AmfDec * dec)
{
  if (dec->version == AMF0_VERSION && amf_dec_peek (dec) == AMF0_SWITCH_AMF3) {
    debug ("entering AMF3 mode\n");
    dec->pos++;
    dec->version = AMF3_VERSION;
  }
  if (dec->pos >= dec->buf->len) {
    g_warning ("%s: Not enough data", __FUNCTION__);
  }
  return dec->buf->data[dec->pos++];
}

static unsigned int
amd_dec_load_amf3_integer (AmfDec * dec)
{
  unsigned int value = 0;
  for (int i = 0; i < 4; ++i) {
    guint8 b = amf_dec_get_byte (dec);
    if (i == 3) {
      /* use all bits from 4th byte */
      value = (value << 8) | b;
      break;
    }
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) == 0)
      break;
  }
  return value;
}

static gchar *
_load_string (AmfDec * dec)
{
  size_t str_len = 0;

  if (dec->version == AMF3_VERSION) {
    str_len = amd_dec_load_amf3_integer (dec) / 2;
  } else {
    if (dec->pos + 2 > dec->buf->len) {
      g_warning ("%s: Not enough data", __FUNCTION__);
    }
    str_len = load_be16 (&dec->buf->data[dec->pos]);
    dec->pos += 2;
  }
  if (dec->pos + str_len > dec->buf->len) {
    g_warning ("%s: Not enough data", __FUNCTION__);
  }
  gchar * s = g_strndup ((const gchar *)&dec->buf->data[dec->pos], str_len);
  dec->pos += str_len;
  return s;
}

gchar *
amf_dec_load_string (AmfDec * dec)
{
  guint8 type = amf_dec_get_byte (dec);

  if (dec->version == AMF3_VERSION) {
    if (type != AMF3_STRING) {
      g_warning ("Expected a string");
    }
  } else if (type != AMF0_STRING) {
    g_warning ("Expected a string");
  }
  return _load_string (dec);
}

gchar *
amf_dec_load_key (AmfDec * dec)
{
  return _load_string (dec);
}

double
amf_dec_load_number (AmfDec * dec)
{
  if (amf_dec_get_byte (dec) != AMF0_NUMBER) {
    g_warning ("Expected a string");
  }
  if (dec->pos + 8 > dec->buf->len) {
    g_warning ("%s: Not enough data", __FUNCTION__);
  }
  uint64_t val = ((uint64_t) load_be32 (&dec->buf->data[dec->pos]) << 32) |
      load_be32 (&dec->buf->data[dec->pos + 4]);
  double n = 0;
#if defined(__i386__) || defined(__x86_64__)
  /* Flash uses same floating point format as x86 */
  memcpy (&n, &val, 8);
#endif
  dec->pos += 8;
  return n;
}

int
amf_dec_load_integer (AmfDec * dec)
{
  if (dec->version == AMF3_VERSION) {
    return amd_dec_load_amf3_integer (dec);
  } else {
    return amf_dec_load_number (dec);
  }
}

gboolean
amf_dec_load_boolean (AmfDec * dec)
{
  if (amf_dec_get_byte (dec) != AMF0_BOOLEAN) {
    g_warning ("Expected a boolean");
  }
  return amf_dec_get_byte (dec) != 0;
}

static void
amf_dec_load_structure (AmfDec * dec, GstStructure * s)
{
  while (1) {
    gchar * key = amf_dec_load_key (dec);
    if (strlen (key) == 0) {
      g_free (key);
      break;
    }
    GValue * value = amf_dec_load (dec);
    gst_structure_set_value (s, key, value);
    g_free (key);
    g_value_unset (value);
    g_free (value);
  }
}

GstStructure *
amf_dec_load_object (AmfDec * dec)
{
  GstStructure * object = gst_structure_empty_new ("object");

  guint8 type = amf_dec_get_byte (dec);
  if (dec->version == AMF0_VERSION && type != AMF0_OBJECT) {
    g_warning ("Expected an object AMF0 object");
  }

  if (dec->version == AMF3_VERSION) {
    if (type != AMF3_OBJECT)
      g_warning ("Expected an object AMF3 object");

    guint8 object_count = amf_dec_get_byte (dec);
    (void)object_count; //FIXME: could use this!
    guint8 start_byte = amf_dec_get_byte (dec);
    if (start_byte != AMF3_NULL)
      g_warning ("expected AMF3 object-start");
  }

  amf_dec_load_structure (dec, object);

  if (dec->version == AMF0_VERSION) {
    if (amf_dec_get_byte (dec) != AMF0_OBJECT_END)
      g_warning ("expected object end");
  }
  return object;
}

GstStructure *
amf_dec_load_ecma (AmfDec * dec)
{
  /* ECMA array is the same as object, with 4 extra zero bytes */
  GstStructure *  object = gst_structure_empty_new ("ecma");
  if (amf_dec_get_byte (dec) != AMF0_ECMA_ARRAY) {
    g_warning ("Expected an ECMA array");
  }
  if (dec->pos + 4 > dec->buf->len) {
    g_warning ("%s: Not enough data", __FUNCTION__);
  }
  dec->pos += 4;
  amf_dec_load_structure (dec, object);

  if (amf_dec_get_byte (dec) != AMF0_OBJECT_END) {
    g_warning ("expected object end");
  }
  return object;
}

GValue *
amf_dec_load (AmfDec * dec)
{
  GValue * value = g_new0 (GValue, 1);
  guint8 type = amf_dec_peek (dec);
  if (dec->version == AMF3_VERSION) {
    switch (type) {
      case AMF3_STRING:
      {
        g_value_init (value, G_TYPE_STRING);
        gchar * string = amf_dec_load_string (dec);
        g_value_set_string (value, string);
        g_free (string);
        break;
      }
      case AMF3_NUMBER:
      {
        g_value_init (value, G_TYPE_DOUBLE);
        g_value_set_double (value, amf_dec_load_number (dec));
        break;
      }
      case AMF3_INTEGER:
      {
        dec->pos++;
        g_value_init (value, G_TYPE_INT);
        g_value_set_int (value, amf_dec_load_integer (dec));
        break;
      }
      case AMF3_FALSE:
      {
        dec->pos++;
        g_value_init (value, G_TYPE_BOOLEAN);
        g_value_set_boolean (value, FALSE);
        break;
      }
      case AMF3_TRUE:
      {
        dec->pos++;
        g_value_init (value, G_TYPE_BOOLEAN);
        g_value_set_boolean (value, TRUE);
        break;
      }
      case AMF3_OBJECT:
      {
        g_value_init (value, GST_TYPE_STRUCTURE);
        GstStructure * s = amf_dec_load_object (dec);
        gst_value_set_structure (value, s);
        gst_structure_free (s);
        break;
      }
      case AMF3_ARRAY:
      {
        g_value_init (value, GST_TYPE_STRUCTURE);
        GstStructure * s = amf_dec_load_ecma (dec);
        gst_value_set_structure (value, s);
        gst_structure_free (s);
        break;
      }
      case AMF3_NULL:
      case AMF3_UNDEFINED:
      {
        dec->pos++;
        break;
      }
      default:
        g_warning ("Unsupported AMF3 type: %02x", type);
    }
  } else {
    switch (type) {
      case AMF0_STRING:
      {
        g_value_init (value, G_TYPE_STRING);
        gchar * string = amf_dec_load_string (dec);
        g_value_set_string (value, string);
        g_free (string);
        break;
      }
      case AMF0_NUMBER:
      {
        g_value_init (value, G_TYPE_DOUBLE);
        g_value_set_double (value, amf_dec_load_number (dec));
        break;
      }
      case AMF0_BOOLEAN:
      {
        g_value_init (value, G_TYPE_BOOLEAN);
        g_value_set_boolean (value, amf_dec_load_boolean (dec));
        break;
      }
      case AMF0_OBJECT:
      {
        g_value_init (value, GST_TYPE_STRUCTURE);
        GstStructure * s = amf_dec_load_object (dec);
        gst_value_set_structure (value, s);
        gst_structure_free (s);
        break;
      }
      case AMF0_ECMA_ARRAY:
      {
        g_value_init (value, GST_TYPE_STRUCTURE);
        GstStructure * s = amf_dec_load_ecma (dec);
        gst_value_set_structure (value, s);
        gst_structure_free (s);
        break;
      }
      case AMF0_NULL:
      case AMF0_UNDEFINED:
      {
        dec->pos++;
        break;
      }
      default:
        g_warning ("Unsupported AMF0 type: %02x", type);
    }
  }

  return value;
}
