/*********************************************
 * vim:sw=8:ts=8:si:et
 * To use the above modeline in vim you must have "set modeline" in your .vimrc
 *
 * Author: Guido Socher 
 * Copyright:LGPL V2
 * See http://www.gnu.org/licenses/old-licenses/lgpl-2.0.html
 *
 * IP, Arp, UDP and TCP functions.
 *
 * The TCP implementation uses some size optimisations which are valid
 * only if all data can be sent in one single packet. This is however
 * not a big limitation for a microcontroller as you will anyhow use
 * small web-pages. The web server must send the entire web page in one
 * packet. The client "web browser" as implemented here can also receive
 * large pages.
 *
 * Chip type           : ATMEGA88/168/328/644 with ENC28J60
 *********************************************/
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "net.h"
#include "enc28j60.h"
#include "my_tcp.h"

//
uint8_t any_mac, macs[3][6];
uint8_t telnet_on, www_on;
uint8_t ready, connected;
uint32_t rd_seq;

uint8_t macaddr[6], cl_mac[6];
uint8_t ipaddr[4], cl_ip[4], cl_port[2];
uint32_t seqnum=0xA000;
uint32_t tl_seqnum=0xA000, cl_seqnum;
static void (*icmp_callback)(uint8_t *ip);
//


//#ifdef WWW_server
static uint8_t wwwport_l=80; // server port
static uint8_t wwwport_h=0;  // Note: never use same as TCPCLIENT_SRC_PORT_H
static uint16_t info_data_len=0;
//#endif

// skr !!!
uint8_t telnetport_l=23; 
uint8_t telnetport_h=0;  
// skr !!!


#define CLIENTMSS 750
#define TCP_DATA_START ((uint16_t)TCP_SRC_PORT_H_P+(buf[TCP_HEADER_LEN_P]>>4)*4)
const char arpreqhdr[] PROGMEM ={0,1,8,0,6,4,0,1};


// The Ip checksum is calculated over the ip header only starting
// with the header length field and a total length of 20 bytes
// unitl ip.dst
// You must set the IP checksum field to zero before you start
// the calculation.
// len for ip is 20.
//
// For UDP/TCP we do not make up the required pseudo header. Instead we 
// use the ip.src and ip.dst fields of the real packet:
// The udp checksum calculation starts with the ip.src field
// Ip.src=4bytes,Ip.dst=4 bytes,Udp header=8bytes + data length=16+len
// In other words the len here is 8 + length over which you actually
// want to calculate the checksum.
// You must set the checksum field to zero before you start
// the calculation.
// The same algorithm is also used for udp and tcp checksums.
// len for udp is: 8 + 8 + data length
// len for tcp is: 4+4 + 20 + option len + data length
//
// For more information on how this algorithm works see:
// http://www.netfor2.com/checksum.html
// http://www.msc.uky.edu/ken/cs471/notes/chap3.htm
// The RFC has also a C code example: http://www.faqs.org/rfcs/rfc1071.html
uint16_t checksum(uint8_t *buf, uint16_t len,uint8_t type){
        // type 0=ip , icmp
        //      1=udp
        //      2=tcp
        uint32_t sum = 0;

        //if(type==0){    
        //        // do not add anything, standard IP checksum as described above
        //        // Usable for ICMP and IP header
        //}
        if(type==1){
                sum+=IP_PROTO_UDP_V; // protocol udp
                // the length here is the length of udp (data+header len)
                // =length given to this function - (IP.scr+IP.dst length)
                sum+=len-8; // = real udp len
        }
        if(type==2){
                sum+=IP_PROTO_TCP_V; 
                // the length here is the length of tcp (data+header len)
                // =length given to this function - (IP.scr+IP.dst length)
                sum+=len-8; // = real tcp len
        }
        // build the sum of 16bit words
        while(len >1){
                sum += 0xFFFF & (((uint32_t)*buf<<8)|*(buf+1));
                buf+=2;
                len-=2;
        }
        // if there is a byte left then add it (padded with zero)
        if (len){
                sum += ((uint32_t)(0xFF & *buf))<<8;
        }
        // now calculate the sum over the bytes in the sum
        // until the result is only 16bit long
        while (sum>>16){
                sum = (sum & 0xFFFF)+(sum >> 16);
        }
        // build 1's complement:
        return( (uint16_t) sum ^ 0xFFFF);
}

uint8_t eth_type_is_arp_and_my_ip(uint8_t *buf,uint16_t len){
        uint8_t i=0;
        //  
        if (len<41){
                return(0);
        }
        if(buf[ETH_TYPE_H_P] != ETHTYPE_ARP_H_V || 
           buf[ETH_TYPE_L_P] != ETHTYPE_ARP_L_V){
                return(0);
        }
        while(i<4){
                if(buf[ETH_ARP_DST_IP_P+i] != ipaddr[i]){
                        return(0);
                }
                i++;
        }
        return(1);
}

uint8_t eth_type_is_ip_and_my_ip(uint8_t *buf,uint16_t len){
        uint8_t i=0;
        //eth+ip+udp header is 42
        if (len<42){
                return(0);
        }
        if(buf[ETH_TYPE_H_P]!=ETHTYPE_IP_H_V || 
           buf[ETH_TYPE_L_P]!=ETHTYPE_IP_L_V){
                return(0);
        }
        if (buf[IP_HEADER_LEN_VER_P]!=0x45){
                // must be IP V4 and 20 byte header
                return(0);
        }
        while(i<4){
                if(buf[IP_DST_P+i]!=ipaddr[i]){
                        return(0);
                }
                i++;
        }
        return(1);
}

// make a return eth header from a received eth packet
void make_eth(uint8_t *buf)
{
        uint8_t i=0;
        //
        //copy the destination mac from the source and fill my mac into src
        while(i<6){
                buf[ETH_DST_MAC +i]=buf[ETH_SRC_MAC +i];
                buf[ETH_SRC_MAC +i]=macaddr[i];
                i++;
        }
}

void fill_ip_hdr_checksum(uint8_t *buf)
{
        uint16_t ck;
        // clear the 2 byte checksum
        buf[IP_CHECKSUM_P]=0;
        buf[IP_CHECKSUM_P+1]=0;
        buf[IP_FLAGS_P]=0x40; // don't fragment
        buf[IP_FLAGS_P+1]=0;  // fragement offset
        buf[IP_TTL_P]=64; // ttl
        // calculate the checksum:
        ck=checksum(&buf[IP_P], IP_HEADER_LEN,0);
        buf[IP_CHECKSUM_P]=ck>>8;
        buf[IP_CHECKSUM_P+1]=ck& 0xff;
}

// make a return ip header from a received ip packet
void make_ip(uint8_t *buf)
{
        uint8_t i=0;
        while(i<4){
                buf[IP_DST_P+i]=buf[IP_SRC_P+i];
                buf[IP_SRC_P+i]=ipaddr[i];
                i++;
        }
        fill_ip_hdr_checksum(buf);
}

// swap seq and ack number and count ack number up
void step_seq(uint8_t *buf,uint16_t rel_ack_num,uint8_t cp_seq)
{
        uint8_t i;
        uint8_t tseq;
        i=4;
        // sequence numbers:
        // add the rel ack num to SEQACK
        while(i>0){
                rel_ack_num=buf[TCP_SEQ_H_P+i-1]+rel_ack_num;
                tseq=buf[TCP_SEQACK_H_P+i-1];
                buf[TCP_SEQACK_H_P+i-1]=0xff&rel_ack_num;
                if (cp_seq){
                        // copy the acknum sent to us into the sequence number
                        buf[TCP_SEQ_H_P+i-1]=tseq;
                }else{
                        buf[TCP_SEQ_H_P+i-1]= 0; // some preset value
                }
                rel_ack_num=rel_ack_num>>8;
                i--;
        }
}

// make a return tcp header from a received tcp packet
// rel_ack_num is how much we must step the seq number received from the
// other side. We do not send more than 765 bytes of text (=data) in the tcp packet.
// No mss is included here.
//
// After calling this function you can fill in the first data byte at TCP_OPTIONS_P+4
// If cp_seq=0 then an initial sequence number is used (should be use in synack)
// otherwise it is copied from the packet we received
void make_tcphead(uint8_t *buf,uint16_t rel_ack_num,uint8_t cp_seq)
{
        uint8_t i;
        // copy ports:
        i=buf[TCP_DST_PORT_H_P];
        buf[TCP_DST_PORT_H_P]=buf[TCP_SRC_PORT_H_P];
        buf[TCP_SRC_PORT_H_P]=i;
        //
        i=buf[TCP_DST_PORT_L_P];
        buf[TCP_DST_PORT_L_P]=buf[TCP_SRC_PORT_L_P];
        buf[TCP_SRC_PORT_L_P]=i;
        step_seq(buf,rel_ack_num,cp_seq);
        // zero the checksum
        buf[TCP_CHECKSUM_H_P]=0;
        buf[TCP_CHECKSUM_L_P]=0;
        // no options:
        // 20 bytes:
        // The tcp header length is only a 4 bit field (the upper 4 bits).
        // It is calculated in units of 4 bytes.
        // E.g 20 bytes: 20/4=6 => 0x50=header len field
        buf[TCP_HEADER_LEN_P]=0x50;
}

void make_arp_answer_from_request(uint8_t *buf)
{
        uint8_t i=0;
        //
        make_eth(buf);
        buf[ETH_ARP_OPCODE_H_P]=ETH_ARP_OPCODE_REPLY_H_V;
        buf[ETH_ARP_OPCODE_L_P]=ETH_ARP_OPCODE_REPLY_L_V;
        // fill the mac addresses:
        while(i<6){
                buf[ETH_ARP_DST_MAC_P+i]=buf[ETH_ARP_SRC_MAC_P+i];
                buf[ETH_ARP_SRC_MAC_P+i]=macaddr[i];
                i++;
        }
        i=0;
        while(i<4){
                buf[ETH_ARP_DST_IP_P+i]=buf[ETH_ARP_SRC_IP_P+i];
                buf[ETH_ARP_SRC_IP_P+i]=ipaddr[i];
                i++;
        }
        // eth+arp is 42 bytes:
        enc28j60PacketSend(42,buf); 
}

void make_echo_reply_from_request(uint8_t *buf,uint16_t len)
{
        make_eth(buf);
        make_ip(buf);
        buf[ICMP_TYPE_P]=ICMP_TYPE_ECHOREPLY_V;
        // we changed only the icmp.type field from request(=8) to reply(=0).
        // we can therefore easily correct the checksum:
        if (buf[ICMP_CHECKSUM_P] > (0xff-0x08)){
                buf[ICMP_CHECKSUM_P+1]++;
        }
        buf[ICMP_CHECKSUM_P]+=0x08;
        //
        enc28j60PacketSend(len,buf);
}

// do some basic length calculations 
uint16_t get_tcp_data_len(uint8_t *buf)
{
        int16_t i;
        i=(((int16_t)buf[IP_TOTLEN_H_P])<<8)|(buf[IP_TOTLEN_L_P]&0xff);
        i-=IP_HEADER_LEN;
        i-=(buf[TCP_HEADER_LEN_P]>>4)*4; // generate len in bytes;
        if (i<=0){
                i=0;
        }
        return((uint16_t)i);
}


// fill in tcp data at position pos. pos=0 means start of
// tcp data. Returns the position at which the string after
// this string could be filled.
uint16_t fill_tcp_data_p(uint8_t *buf,uint16_t pos, const char *progmem_s)
{
        char c;
        // fill in tcp data at position pos
        //
        // with no options the data starts after the checksum + 2 more bytes (urgent ptr)
        while ((c = pgm_read_byte(progmem_s++))) {
                buf[TCP_CHECKSUM_L_P+3+pos]=c;
                pos++;
        }
        return(pos);
}

// fill a binary string of len data into the tcp packet
uint16_t fill_tcp_data_len(uint8_t *buf,uint16_t pos, const uint8_t *s, uint8_t len)
{
        // fill in tcp data at position pos
        //
        // with no options the data starts after the checksum + 2 more bytes (urgent ptr)
        while (len) {
                buf[TCP_CHECKSUM_L_P+3+pos]=*s;
                pos++;
                s++;
                len--;
        }
        return(pos);
}

// fill in tcp data at position pos. pos=0 means start of
// tcp data. Returns the position at which the string after
// this string could be filled.
uint16_t fill_tcp_data(uint8_t *buf,uint16_t pos, const char *s)
{
        return(fill_tcp_data_len(buf,pos,(uint8_t*)s,strlen(s)));
}

// Make just an ack packet with no tcp data inside
// This will modify the eth/ip/tcp header 
void make_tcp_ack_from_any(uint8_t *buf,int16_t datlentoack,uint8_t addflags)
{
        uint16_t j;

        make_eth(buf);
        // fill the header:
        buf[TCP_FLAGS_P]=TCP_FLAGS_ACK_V|addflags;
        if (addflags==TCP_FLAGS_RST_V){
                make_tcphead(buf,datlentoack,1); 
        }else{
                if (datlentoack==0){
                        // if there is no data then we must still acknoledge one packet
                        datlentoack=1;
                }
                // normal case, ack the data:
                make_tcphead(buf,datlentoack,1); // no options
        }
        // total length field in the IP header must be set:
        // 20 bytes IP + 20 bytes tcp (when no options) 
        j=IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN;
        buf[IP_TOTLEN_H_P]=j>>8;
        buf[IP_TOTLEN_L_P]=j& 0xff;
        make_ip(buf);
        // use a low window size otherwise we have to have
        // timers and can not just react on every packet.
        //buf[TCP_WIN_SIZE]=0x4; // 1024=0x400, 1280=0x500 2048=0x800 768=0x300
        buf[TCP_WIN_SIZE]=4; // 255 skr !!!
        buf[TCP_WIN_SIZE+1]=0;
        // calculate the checksum, len=8 (start from ip.src) + TCP_HEADER_LEN_PLAIN + data len
        j=checksum(&buf[IP_SRC_P], 8+TCP_HEADER_LEN_PLAIN,2);
        buf[TCP_CHECKSUM_H_P]=j>>8;
        buf[TCP_CHECKSUM_L_P]=j& 0xff;
        enc28j60PacketSend(IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+ETH_HEADER_LEN,buf);
}


// dlen is the amount of tcp data (http data) we send in this packet
// You can use this function only immediately after make_tcp_ack_from_any
// This is because this function will NOT modify the eth/ip/tcp header except for
// length and checksum
// You must set TCP_FLAGS before calling this
void make_tcp_ack_with_data_noflags(uint8_t *buf,uint16_t dlen)
{
        uint16_t j;
        // total length field in the IP header must be set:
        // 20 bytes IP + 20 bytes tcp (when no options) + len of data
        j=IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+dlen;
        buf[IP_TOTLEN_H_P]=j>>8;
        buf[IP_TOTLEN_L_P]=j& 0xff;
        fill_ip_hdr_checksum(buf);
        // zero the checksum
        buf[TCP_CHECKSUM_H_P]=0;
        buf[TCP_CHECKSUM_L_P]=0;
        // calculate the checksum, len=8 (start from ip.src) + TCP_HEADER_LEN_PLAIN + data len
        j=checksum(&buf[IP_SRC_P], 8+TCP_HEADER_LEN_PLAIN+dlen,2);
        buf[TCP_CHECKSUM_H_P]=j>>8;
        buf[TCP_CHECKSUM_L_P]=j& 0xff;
        enc28j60PacketSend(IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+dlen+ETH_HEADER_LEN,buf);
}


// This initializes server
// you must call this function once before you use any of the other functions:
// mymac may be NULL and can be used if you did already call init_mac
void init_mac_ip(uint8_t *mymac, uint8_t *myip)
{
  ipaddr[0] = myip[0];  ipaddr[1] = myip[1];
  ipaddr[2] = myip[2];  ipaddr[3] = myip[3];

  macaddr[0] = mymac[0];  macaddr[1] = mymac[1];
  macaddr[2] = mymac[2];  macaddr[3] = mymac[3];
  macaddr[4] = mymac[4];  macaddr[5] = mymac[5];
}

// skr !!!
void telnet_server_start(uint16_t port)
{
        telnetport_h=(port>>8)&0xff;
        telnetport_l=(port&0xff);
        telnet_on=1;
}
// skr !!!


// not needed if you want port 80 (the default is port 80):
void www_server_start(uint16_t port)
{
        wwwport_h=(port>>8)&0xff;
        wwwport_l=(port&0xff);
        www_on=1;
}

// this is for the server not the client:
void make_tcp_synack_from_syn(uint8_t *buf)
{
        uint16_t ck;

        make_eth(buf);
        // total length field in the IP header must be set:
        // 20 bytes IP + 24 bytes (20tcp+4tcp options)
        buf[IP_TOTLEN_H_P]=0;
        buf[IP_TOTLEN_L_P]=IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+4;
        make_ip(buf);
        buf[TCP_FLAGS_P]=TCP_FLAGS_SYNACK_V;
        make_tcphead(buf,1,0);
        // put an inital seq number
        buf[TCP_SEQ_H_P+0]= 0;
        buf[TCP_SEQ_H_P+1]= 0;
        // we step only the second byte, this allows us to send packts 
        // with 255 bytes, 512  or 765 (step by 3) without generating
        // overlapping numbers.
        buf[TCP_SEQ_H_P+2]= seqnum>>8; 
        buf[TCP_SEQ_H_P+3]= seqnum;
        // step the inititial seq num by something we will not use
        // during this tcp session:
        //seqnum+=3;
        seqnum+=1; // skr !!!
        // add an mss options field with MSS to 1280:
        // 1280 in hex is 0x500
        buf[TCP_OPTIONS_P]=2;
        buf[TCP_OPTIONS_P+1]=4;
        buf[TCP_OPTIONS_P+2]=0x05;
        buf[TCP_OPTIONS_P+3]=0x0;
        // The tcp header length is only a 4 bit field (the upper 4 bits).
        // It is calculated in units of 4 bytes.
        // E.g 24 bytes: 24/4=6 => 0x60=header len field
        buf[TCP_HEADER_LEN_P]=0x60;
        // here we must just be sure that the web browser contacting us
        // will send only one get packet

        //buf[TCP_WIN_SIZE]=0x0a; // was 1400=0x578, 2560=0xa00 suggested by Andras Tucsni to be able to receive bigger packets
        buf[TCP_WIN_SIZE]=4; // 255 skr !!!
        buf[TCP_WIN_SIZE+1]=0; //
        // calculate the checksum, len=8 (start from ip.src) + TCP_HEADER_LEN_PLAIN + 4 (one option: mss)
        ck=checksum(&buf[IP_SRC_P], 8+TCP_HEADER_LEN_PLAIN+4,2);
        buf[TCP_CHECKSUM_H_P]=ck>>8;
        buf[TCP_CHECKSUM_L_P]=ck& 0xff;
        // add 4 for option mss:
        enc28j60PacketSend(IP_HEADER_LEN+TCP_HEADER_LEN_PLAIN+4+ETH_HEADER_LEN,buf);
}

// skr !!!
void telnet_server_send(uint8_t *buf, uint16_t dlen)
{
  if(telnet_on == 0) return;
  PORTB |= 1;

  uint16_t l = s_make_tcp(buf, dlen, TCP_FLAGS_ACK_V | TCP_FLAGS_PUSH_V);
  enc28j60PacketSend(l, buf);
  ready = 0; PORTD &= ~_BV(PD7);
  rd_seq = tl_seqnum;

  PORTB &= ~1;
}

// you must have initialized info_data_len at some time before calling this function
//
// This info_data_len initialisation is done automatically if you call 
// packetloop_icmp_tcp(buf,enc28j60PacketReceive(BUFFER_SIZE, buf));
// and test the return value for non zero.
//
// dlen is the amount of tcp data (http data) we send in this packet
// You can use this function only immediately after make_tcp_ack_from_any
// This is because this function will NOT modify the eth/ip/tcp header except for
// length and checksum
void www_server_reply(uint8_t *buf,uint16_t dlen)
{
        if(www_on == 0) return;
        make_tcp_ack_from_any(buf,info_data_len,0); // send ack for http get
        // fill the header:
        // This code requires that we send only one data packet
        // because we keep no state information. We must therefore set
        // the fin here:
        buf[TCP_FLAGS_P]=TCP_FLAGS_ACK_V|TCP_FLAGS_PUSH_V|TCP_FLAGS_FIN_V;
        make_tcp_ack_with_data_noflags(buf,dlen); // send data
}

void register_ping_rec_callback(void (*callback)(uint8_t *srcip))
{
        icmp_callback=callback;
}

// return 0 to just continue in the packet loop and return the position 
// of the tcp data if there is tcp data part
uint16_t packetloop_arp_icmp_tcp(uint8_t *buf,uint16_t plen,uint16_t *data_len,uint8_t *type)
{
  *type = 0; // ARP...

        uint16_t len;
        // arp is broadcast if unknown but a host may also
        // verify the mac address by sending it to 
        // a unicast address.
        if(eth_type_is_arp_and_my_ip(buf,plen)){
                if (buf[ETH_ARP_OPCODE_L_P]==ETH_ARP_OPCODE_REQ_L_V){
                        // is it an arp request 
                        make_arp_answer_from_request(buf);
                }
                return(0);

        }
        // check if ip packets are for us:
        if(eth_type_is_ip_and_my_ip(buf,plen)==0){
                return(0);
        }
        if(buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V){
                if (icmp_callback){
                        (*icmp_callback)(&(buf[IP_SRC_P]));
                }
                // a ping packet, let's send pong
                make_echo_reply_from_request(buf,plen);
                return(0);
        }
        // this is an important check to avoid working on the wrong packets:
        if (plen<54 || buf[IP_PROTO_P]!=IP_PROTO_TCP_V ){
                // smaller than the smallest TCP packet (TCP packet with no options section) or not tcp port
                return(0);
        }
        //


        // check for allowed macs. skr
        if(!any_mac)
        {
          if( !( (macs[0][0]==buf[ETH_SRC_MAC+0] && macs[0][1]==buf[ETH_SRC_MAC+1] && macs[0][2]==buf[ETH_SRC_MAC+2] &&
                  macs[0][3]==buf[ETH_SRC_MAC+3] && macs[0][4]==buf[ETH_SRC_MAC+4] && macs[0][5]==buf[ETH_SRC_MAC+5])
                   ||
                 (macs[1][0]==buf[ETH_SRC_MAC+0] && macs[1][1]==buf[ETH_SRC_MAC+1] && macs[1][2]==buf[ETH_SRC_MAC+2] &&
                  macs[1][3]==buf[ETH_SRC_MAC+3] && macs[1][4]==buf[ETH_SRC_MAC+4] && macs[1][5]==buf[ETH_SRC_MAC+5])
                   ||
                 (macs[2][0]==buf[ETH_SRC_MAC+0] && macs[2][1]==buf[ETH_SRC_MAC+1] && macs[2][2]==buf[ETH_SRC_MAC+2] &&
                  macs[2][3]==buf[ETH_SRC_MAC+3] && macs[2][4]==buf[ETH_SRC_MAC+4] && macs[2][5]==buf[ETH_SRC_MAC+5]) )
            ) return 0;
        }
        


        // tcp port web server start
//        if (buf[TCP_DST_PORT_H_P]==wwwport_h && buf[TCP_DST_PORT_L_P]==wwwport_l)
        if (buf[TCP_DST_PORT_H_P]==wwwport_h && buf[TCP_DST_PORT_L_P]==wwwport_l && www_on)
        {
                *type = 1; // WWW
                if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V){
                        make_tcp_synack_from_syn(buf);
                        // make_tcp_synack_from_syn does already send the syn,ack
                        return(0);
                }
                if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V){
                        info_data_len=get_tcp_data_len(buf);
                        // we can possibly have no data, just ack:
                        // Here we misuse plen for something else to save a variable.
                        // plen is now the position of start of the tcp user data.
                        if (info_data_len==0){
                                if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V){
                                        // finack, answer with ack
                                        make_tcp_ack_from_any(buf,0,0);
                                }
                                // just an ack with no data, wait for next packet
                                return(0);
                        }
                        // Here we misuse len for something else to save a variable
                        len=TCP_DATA_START; // TCP_DATA_START is a formula
                        // check for data corruption
                        if (len>plen-8){
                                return(0);
                        }
                        return(len);
                }
        }

  // skr !!! telnet

  static uint8_t syn=0, fin=0;

//  if (buf[TCP_DST_PORT_H_P]==telnetport_h && buf[TCP_DST_PORT_L_P]==telnetport_l)
  if (buf[TCP_DST_PORT_H_P]==telnetport_h && buf[TCP_DST_PORT_L_P]==telnetport_l && telnet_on)
  {

    if (buf[TCP_FLAGS_P] & TCP_FLAGS_RST_V)
    {
      connected = 0;
      syn = 0;
      ready = 0;
      return 0;
    }
    
    if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V && connected)
    {
      cl_seqnum++;
      uint16_t l = s_make_tcp(buf, 0, TCP_FLAGS_RST_V);
      enc28j60PacketSend(l, buf);
      connected = 0;
      syn = 0;
    }
    
    *type = 2; // telnet
    uint16_t l;

    cl_seqnum = ((uint32_t)buf[TCP_SEQ_H_P]<<24) | ((uint32_t)buf[TCP_SEQ_H_P+1]<<16) |
                ((uint32_t)buf[TCP_SEQ_H_P+2]<<8) | (uint32_t)buf[TCP_SEQ_H_P+3];

    uint32_t s;
        s = ((uint32_t)buf[TCP_SEQACK_H_P]<<24) | ((uint32_t)buf[TCP_SEQACK_H_P+1]<<16) |
            ((uint32_t)buf[TCP_SEQACK_H_P+2]<<8) | (uint32_t)buf[TCP_SEQACK_H_P+3];

    if (buf[TCP_FLAGS_P] & (TCP_FLAGS_SYN_V | TCP_FLAGS_FIN_V | TCP_FLAGS_ACK_V))
    {
      cl_mac[0] = buf[ETH_SRC_MAC];    cl_mac[1] = buf[ETH_SRC_MAC+1];
      cl_mac[2] = buf[ETH_SRC_MAC+2];  cl_mac[3] = buf[ETH_SRC_MAC+3];
      cl_mac[4] = buf[ETH_SRC_MAC+4];  cl_mac[5] = buf[ETH_SRC_MAC+5];
      cl_ip[0] =  buf[IP_SRC_P];        cl_ip[1] =  buf[IP_SRC_P+1];
      cl_ip[2] =  buf[IP_SRC_P+2];      cl_ip[3] =  buf[IP_SRC_P+3];
      cl_port[0] = buf[TCP_SRC_PORT_H_P];  cl_port[1] = buf[TCP_SRC_PORT_L_P];
    }
  
    if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V)
    {
      cl_seqnum++;
      l = s_make_tcp(buf, 0, TCP_FLAGS_SYNACK_V);
      enc28j60PacketSend(l, buf);
      tl_seqnum++;
      connected = 1;
      syn = 1; 
      ready = 1; PORTD |= _BV(PD7);
      //PORTC |= (1<<PORTC0); // set pin to 1
      return(0);
    }

    if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V)
    {

      if(!connected && !fin)
      {
        tl_seqnum = s;
        l = s_make_tcp(buf, 0, TCP_FLAGS_RST_V); // ACK
        enc28j60PacketSend(l, buf);
        return 0;
      }

      if(fin)
      {
        connected = 0;
        fin = 0;
      }

      if(rd_seq == s){ ready = 1; PORTD |= _BV(PD7); }
      
      info_data_len = get_tcp_data_len(buf);
      *data_len = info_data_len;

      if (info_data_len != 0)
      {
        len = TCP_DATA_START; 
        //make_tcp_ack_from_any(buf, info_data_len, 0);
        cl_seqnum += info_data_len;
        l = s_make_tcp(buf, 0, TCP_FLAGS_ACK_V); // ACK
        enc28j60PacketSend(l, buf);
        return(len);
      }

      if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V)
      {
        tl_seqnum = ((uint32_t)buf[TCP_SEQACK_H_P]<<24) | ((uint32_t)buf[TCP_SEQACK_H_P+1]<<16) |
            ((uint32_t)buf[TCP_SEQACK_H_P+2]<<8) | (uint32_t)buf[TCP_SEQACK_H_P+3];

        cl_seqnum++;
        l = s_make_tcp(buf, 0, TCP_FLAGS_ACK_V); // ACK
        enc28j60PacketSend(l, buf);
        l = s_make_tcp(buf, 0, TCP_FLAGS_FIN_V | TCP_FLAGS_ACK_V); // FIN, ACK
        enc28j60PacketSend(l, buf);

        //connected = 0;
        fin = 1;
        return 0;
      }

      if(syn == 1)
      {
        syn = 0;
        uint16_t ll;
        ll = fill_tcp_data(buf,0,">");
        telnet_server_send(buf,ll);
        return 0;
      }
       
    }
  }
  
  return(0);
}
/* end of ip_arp_udp.c */
