#ifndef _FIFO_H_
#define _FIFO_H_

#include <stdint.h>

typedef struct
{
  uint8_t *in_buf;
  uint8_t *in_ptr, *out_ptr;
  uint8_t size, full;
} FIFO;

void fifo_init(FIFO *f, uint8_t *buf, uint8_t sz);
uint8_t fifo_push(FIFO *f, uint8_t b);
uint8_t fifo_pop(FIFO *f, uint8_t *buf);
uint8_t fifo_pop_one(FIFO *f, uint8_t *buf);

#endif
