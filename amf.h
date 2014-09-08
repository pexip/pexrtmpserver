#ifndef __amf_h
#define __amf_h

#include <gst/gst.h>

enum AMFType
{
  AMF_NUMBER,
  AMF_INTEGER,
  AMF_BOOLEAN,
  AMF_STRING,
  AMF_OBJECT,
  AMF_NULL,
  AMF_UNDEFINED,
  AMF_ECMA_ARRAY,
};

enum AMF0Type
{
  AMF0_NUMBER,
  AMF0_BOOLEAN,
  AMF0_STRING,
  AMF0_OBJECT,
  AMF0_MOVIECLIP,
  AMF0_NULL,
  AMF0_UNDEFINED,
  AMF0_REFERENCE,
  AMF0_ECMA_ARRAY,
  AMF0_OBJECT_END,
  AMF0_STRICT_ARRAY,
  AMF0_DATE,
  AMF0_LONG_STRING,
  AMF0_UNSUPPORTED,
  AMF0_RECORD_SET,
  AMF0_XML_OBJECT,
  AMF0_TYPED_OBJECT,
  AMF0_SWITCH_AMF3,
};

enum
{
  AMF3_UNDEFINED,
  AMF3_NULL,
  AMF3_FALSE,
  AMF3_TRUE,
  AMF3_INTEGER,
  AMF3_NUMBER,
  AMF3_STRING,
  AMF3_LEGACY_XML,
  AMF3_DATE,
  AMF3_ARRAY,
  AMF3_OBJECT,
  AMF3_XML,
  AMF3_BYTE_ARRAY,
};

#define AMF0_VERSION 0
#define AMF3_VERSION 3

struct _AmfDec
{
  GByteArray * buf;
  size_t pos;
  gint version;
};

struct _AmfEnc
{
  GByteArray * buf;
  gint version;
};


typedef struct _AmfDec AmfDec;
typedef struct _AmfEnc AmfEnc;

AmfEnc * amf_enc_new ();
void amf_enc_free (AmfEnc * enc);
void amf_enc_use_amf3 (AmfEnc * enc);

void amf_enc_add_short (AmfEnc * enc, guint16 s);
void amf_enc_add_int (AmfEnc * enc, guint32 i);

void amf_enc_write_string (AmfEnc * enc, const gchar * str);
void amf_enc_write_double (AmfEnc * enc, double n);
void amf_enc_write_bool (AmfEnc * enc, gboolean b);
void amf_enc_write_key (AmfEnc * enc, const gchar * str);
void amf_enc_write_object (AmfEnc * enc, const GstStructure * object);
void amf_enc_write_ecma (AmfEnc * enc, const GstStructure * object);
void amf_enc_write_null (AmfEnc * enc);
void amf_enc_write_value (AmfEnc * enc, const GValue * value);

AmfDec * amf_dec_new (GByteArray * buf, guint pos);
void amf_dec_free (AmfDec * dec);

gchar * amf_dec_load_string (AmfDec * dec);
double amf_dec_load_number (AmfDec * dec);
int amf_dec_load_integer (AmfDec * dec);
gboolean amf_dec_load_boolean (AmfDec * dec);
gchar * amf_dec_load_key (AmfDec * dec);
GstStructure * amf_dec_load_object (AmfDec * dec);
GstStructure * amf_dec_load_ecma (AmfDec * dec);
GValue * amf_dec_load (AmfDec * dec);

#endif
