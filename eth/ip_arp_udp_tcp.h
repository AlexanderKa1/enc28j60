/*********************************************
 * vim:sw=8:ts=8:si:et
 * To use the above modeline in vim you must have "set modeline" in your .vimrc
 * Author: Guido Socher 
 * Copyright:LGPL V2
 * See http://www.gnu.org/licenses/old-licenses/lgpl-2.0.html
 *
 * IP/ARP/UDP/TCP functions
 *
 * Chip type           : ATMEGA88/168/328/644 with ENC28J60
 *********************************************/
//@{
#ifndef IP_ARP_UDP_TCP_H
#define IP_ARP_UDP_TCP_H 1
//#include "ip_config.h"
#include <avr/pgmspace.h>

extern uint8_t any_mac, macs[3][6];


// -- web server functions --
// you must call this function once before you use any of the other server functions:
// mymac may be set to NULL in this function if init_mac was used before
// init_ip_arp_udp_tcp is now replaced by init_udp_or_www_server  and the www_server_port function.
extern void init_mac_ip(uint8_t *mymac,uint8_t *myip);

// skr !!!
extern void telnet_server_start(uint16_t port); 
void telnet_server_send(uint8_t *buf, uint16_t dlen);
// skr !!!

extern void www_server_start(uint16_t port); // not needed if you want port 80
// send data from the web server to the client:
extern void www_server_reply(uint8_t *buf,uint16_t dlen);

extern uint8_t eth_type_is_ip_and_my_ip(uint8_t *buf,uint16_t len);
// return 0 to just continue in the packet loop and return the position 
// of the tcp data if there is tcp data part:
extern uint16_t packetloop_arp_icmp_tcp(uint8_t *buf,uint16_t plen,uint16_t *len,uint8_t *type);
// functions to fill the web pages with data:
extern uint16_t fill_tcp_data_p(uint8_t *buf,uint16_t pos, const char *progmem_str_p);
extern uint16_t fill_tcp_data(uint8_t *buf,uint16_t pos, const char *s);
// fill a binary string of len data into the tcp packet:
extern uint16_t fill_tcp_data_len(uint8_t *buf,uint16_t pos, const uint8_t *s, uint8_t len);

void fill_ip_hdr_checksum(uint8_t *buf);
uint16_t checksum(uint8_t *buf, uint16_t len,uint8_t type);



#endif /* IP_ARP_UDP_TCP_H */
//@}
