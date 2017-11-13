#include <avr/io.h>
#include "ip_arp_udp_tcp.h"
#include "net.h"

extern uint8_t macaddr[6], cl_mac[6];
extern uint8_t ipaddr[4], cl_ip[4], cl_port[2];
extern uint32_t tl_seqnum, cl_seqnum;
extern uint8_t telnetport_l; 
extern uint8_t telnetport_h;  


uint16_t s_make_tcp(uint8_t *buf, uint16_t dlen, uint8_t flags)
{
  uint8_t i;
  uint16_t j;

  //--- ETHERNET ---
  i = 0;
  while(i<6)
  {
    buf[ETH_SRC_MAC +i] = macaddr[i];
    buf[ETH_DST_MAC +i] = cl_mac[i];
    i++;
  }
  buf[ETH_TYPE_H_P] = 0x08;
  buf[ETH_TYPE_L_P] = 0x00;

  //--- IP ---
  buf[IP_HEADER_LEN_VER_P] = 0x45; // VER, IHL
  buf[IP_TOS_P] = 0; //type of service
  buf[IP_FLAGS_P] = 0x40; // don't fragment
  buf[IP_FLAGS_P+1] = 0;  // fragement offset
  buf[IP_TTL_P] = 64; // TTL
  buf[IP_PROTO_P] = 6; // TCP=6
  i = 0;
  while(i<4)
  {
    buf[IP_SRC_P+i] = ipaddr[i];
    buf[IP_DST_P+i] = cl_ip[i];
    i++;
  }

  //--- TCP ---
  buf[TCP_SRC_PORT_H_P] = telnetport_h; // source port
  buf[TCP_SRC_PORT_L_P] = telnetport_l; 
  buf[TCP_DST_PORT_H_P] = cl_port[0]; // dest port
  buf[TCP_DST_PORT_L_P] = cl_port[1];

  buf[TCP_SEQ_H_P+0] = tl_seqnum>>24; // sequence number
  buf[TCP_SEQ_H_P+1] = tl_seqnum>>16;
  buf[TCP_SEQ_H_P+2] = tl_seqnum>>8;
  buf[TCP_SEQ_H_P+3] = tl_seqnum;
  tl_seqnum += dlen;
  
  buf[TCP_SEQACK_H_P+0] = cl_seqnum>>24; // acknowledge number
  buf[TCP_SEQACK_H_P+1] = cl_seqnum>>16;
  buf[TCP_SEQACK_H_P+2] = cl_seqnum>>8;
  buf[TCP_SEQACK_H_P+3] = cl_seqnum;

  buf[TCP_HEADER_LEN_P]=0x50; // header length
  buf[TCP_FLAGS_P] = flags; // flags
  buf[TCP_WIN_SIZE] = 0x0; // window size = 255
  buf[TCP_WIN_SIZE+1] = 0xFF;
  buf[TCP_CHECKSUM_H_P]=0; // zero the checksum
  buf[TCP_CHECKSUM_L_P]=0;
  buf[TCP_UP_H_P] = 0; // urgent pointer
  buf[TCP_UP_L_P] = 0;

  // IP total length
  j = IP_HEADER_LEN + TCP_HEADER_LEN_PLAIN + dlen;
  buf[IP_TOTLEN_H_P] = j>>8;
  buf[IP_TOTLEN_L_P] = j& 0xff;
  // IP checksum
  fill_ip_hdr_checksum(buf);

  // calculate the checksum, len=8 (start from ip.src) + TCP_HEADER_LEN_PLAIN + data len
  j = checksum(&buf[IP_SRC_P], 8+TCP_HEADER_LEN_PLAIN+dlen, 2);
  buf[TCP_CHECKSUM_H_P] = j>>8;
  buf[TCP_CHECKSUM_L_P] = j& 0xff;

  return IP_HEADER_LEN + TCP_HEADER_LEN_PLAIN + ETH_HEADER_LEN + dlen;
}
