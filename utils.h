#ifndef __utils_h
#define __utils_h

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define debug(fmt...)	\
	fprintf(stderr, fmt)

uint32_t load_be32 (const void *p);
uint16_t load_be16 (const void *p);
uint32_t load_be24 (const void *p);
uint32_t load_le32 (const void *p);
void set_be24 (void *p, uint32_t val);
void set_le32 (void *p, uint32_t val);

#endif
