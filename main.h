#ifndef _MAIN_H_
#define _MAIN_H_

// default MAC address
#define DEF_MAC0 0x00
#define DEF_MAC1 0x01
#define DEF_MAC2 0x02
#define DEF_MAC3 0x03
#define DEF_MAC4 0x04
#define DEF_MAC5 0x05

// default IP address
#define DEF_IP0 192
#define DEF_IP1 168
#define DEF_IP2 1
#define DEF_IP3 19

// default MAC1 address
#define DEF_MAC10 0x11
#define DEF_MAC11 0x22
#define DEF_MAC12 0x33
#define DEF_MAC13 0x44
#define DEF_MAC14 0x55
#define DEF_MAC15 0x66

// default MAC2 address
#define DEF_MAC20 0x22
#define DEF_MAC21 0x33
#define DEF_MAC22 0x44
#define DEF_MAC23 0x55
#define DEF_MAC24 0x66
#define DEF_MAC25 0x77

// default MAC3 address
#define DEF_MAC30 0x33
#define DEF_MAC31 0x44
#define DEF_MAC32 0x55
#define DEF_MAC33 0x66
#define DEF_MAC34 0x77
#define DEF_MAC35 0x88

// default telnet port
#define DEF_PORT 23

// default baud rate
#define DEF_BAUD 9600
// default web password
#define DEF_PASSWORD "12345"

// UART FIFO SIZE
#define IN_SIZE 255

typedef struct
{
  uint8_t  mac_addr[6];
  uint8_t  ip_addr[4];
  uint8_t  mac[3][6];
  uint8_t  mac_any;
  uint16_t telnet_port;
  uint32_t baud_rate;
  char     password[16];
} SET_T;
extern SET_T set;

extern uint8_t ebuf[];

void update_ee(SET_T *s);

#endif