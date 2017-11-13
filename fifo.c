#include <string.h>
#include <avr/io.h>
#include "fifo.h"

void fifo_init(FIFO *f, uint8_t *buf, uint8_t sz)
{
  f->in_buf = f->in_ptr = f->out_ptr = buf;
  f->size = sz;
  f->full = 0;
}

uint8_t fifo_push(FIFO *f, uint8_t b)
{
  if(f->full >= f->size) return -1;
  *f->in_ptr++ = b;
  if(f->in_ptr >= f->in_buf+f->size) f->in_ptr = f->in_buf;
  f->full++;
  return 0;
}

uint8_t fifo_pop(FIFO *f, uint8_t *buf)
{
  uint8_t s = f->full, d;

  if(s == 0) return 0;

  d = f->in_buf + f->size - f->out_ptr;
  if(s > d) 
  {
    memcpy((void*)buf, (void*)f->out_ptr, d);
    memcpy((void*)(buf + d), (void*)f->in_buf, s-d);
  }
  else
  {
    memcpy((void*)buf, (void*)f->out_ptr, s);
  }
  f->out_ptr += s;
  if(f->out_ptr >= f->in_buf + f->size) f->out_ptr -= f->size;
  f->full = 0;

  return s;
}

uint8_t fifo_pop_one(FIFO *f, uint8_t *buf)
{
  if(f->full == 0) return 0;

  *buf = *f->out_ptr;
  f->out_ptr++;
  if(f->out_ptr >= f->in_buf + f->size) f->out_ptr -= f->size;
  f->full--;

  return 1;
}
