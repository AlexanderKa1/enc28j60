#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <string.h>
#include <stdlib.h>

#include "eth/ip_arp_udp_tcp.h"
#include "fifo.h"
#include "main.h"
#include "http.h"

uint8_t state;
char *pbuf;

char buf_str[16]; //111.222.333.444 or password

SET_T new;

uint16_t http200ok(void)
{
  return(fill_tcp_data_p(ebuf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n")));
}
//---
const prog_char head[]="\
<HTML><HEAD><TITLE>Telnet</TITLE>\
</HEAD><BODY>";

//---
const prog_char login[]="\
<form action=\"log\" method=get><br><br>\
<center><H2>Welcome</H2><br><br>\
Enter password:&nbsp;&nbsp;<input type=password name=pass>\
&nbsp;&nbsp;<input type=submit value=\"Enter\" name=submit>\
<br/><br/><br/>&copy 2017 by BSH-Systems. www.bsh-systems.ru\
</center></form></body></HTML>";

const prog_char set1[]="\
<center><br/>\
<form action=\"set\" method=get>\
<table>\
<br><br>\
<tr><td><b><u>Network</u></b></td></tr>\
<tr><td>MAC address:</td><td><input name=mac maxlength=12 value=";
// 001122334455

const prog_char set2[]="\
></td></tr>\
<tr><td>IP address:</td><td><input name=ipaddr maxlength=15 value=";
//192.168.1.255

const prog_char set3[]="\
></td></tr>\
<tr><td>MAC 1:</td><td><input name=mac1 maxlength=12 value=";
// 001122334455

const prog_char set35[]="\
></td></tr>\
<tr><td>MAC 2:</td><td><input name=mac2 maxlength=12 value=";
// 001122334455

const prog_char set36[]="\
></td></tr>\
<tr><td>MAC 3:</td><td><input name=mac3 maxlength=12 value=";
// 001122334455

const prog_char set37[]="\
></td></tr>\
<tr><td>Any MAC:</td><td><input name=any_ type=checkbox ";

const prog_char set4[]="\
></td></tr>\
<tr><td>Telnet port:</td><td><input name=port maxlength=5 value=";
// 23

const prog_char set5[]="\
></td></tr>\
<tr><td>&nbsp;</td></tr>\
<tr><td><b><u>UART</u></b></td></tr>\
<tr><td>Baud rate:</td><td><input name=baud maxlength=7 value=";
//9600

const prog_char set6[]="\
></td></tr>\
<tr><td>&nbsp;</td></tr>\
<tr><td><b><u>Security</u></b></td></tr>\
<tr><td>Password: <td><input type=password maxlength=16 name=pass1></td></tr>\
<tr><td>Re-enter: <td><input type=password maxlength=16 name=pass2></td></tr>\
</table>\
<br><br><input type=submit value=\"Save settings\" name=submit>\
</form>\
</center>\
</body>\
</HTML>";

//---
const prog_char saved[]="\
<br><br><center><H2>Settings saved. Need reboot!</H2>\
</center></body></HTML>";


void putch(char c)
{
//  while(!(UCSR0A&_BV(UDRE0)));
//  UDR0 = c;  
}

void putstr(char *s)
{
  while(*s != 0) putch(*s++);
}

void putstrln(char *s)
{
  putstr(s); 
  putch(10); 
  putch(13);
}

void putdigit(uint8_t d)
{
  putch('0'+d);
}

uint8_t str_cmp(char *buf, char *str, uint8_t n)
{
  uint8_t i;
  for(i=0; i<n; i++)
    if(buf[i] != str[i]) break;
  if(i == n) return 1;
  else return 0;
}

/*void start_send(char *buf, uint16_t len)
{
  pbuf = buf; size = len;
  if(size > uip_mss())
  {
    sent = uip_mss();
    left = size - uip_mss();
  }
  else
  {
    sent = size;
    left = 0;
  }
  uip_send(pbuf, sent);
} */

uint8_t find_param(char *buf, char *name, char *dest)
{
  uint8_t i, len=strlen(name), cnt=0;

  for(i=0; i<200; i++)
    if(str_cmp(&buf[i], name, len) && buf[i+len]=='=') break;
  if(i == 200) return 0;

  i += len + 1;
  for(; i<200; i++)
  {
    if(buf[i]=='&' || buf[i]==' '){ *dest=0; break; }
    *dest++ = buf[i];
    cnt++;
  }

  return cnt;
}

char* str_cpy(char *buf, char *str)
{
  while(*str) *buf++ = *str++;
  *buf = 0;
  return buf;
}

char* str_cpy_fl(char *buf, const prog_char *str)
{
  uint8_t c;
  while((c=pgm_read_byte(str))){ *buf++ = c; str++; }
  *buf = 0;
  return buf;
}

uint16_t send_login(uint8_t *buf)
{
  uint16_t len;
  len = fill_tcp_data_p(ebuf,0,head);
  len = fill_tcp_data_p(ebuf,len,login);
  state = 1;
  return len;
} 

uint16_t send_set(uint8_t *buf)
{
  uint16_t l=0;

  l = fill_tcp_data_p(ebuf,0,head);       
  l = fill_tcp_data_p(ebuf,l,set1);       
  mac_to_str(buf_str, set.mac_addr);
  l = fill_tcp_data(ebuf,l,buf_str);       

  l = fill_tcp_data_p(ebuf,l,set2);       
  ip_to_str(buf_str, set.ip_addr);
  l = fill_tcp_data(ebuf,l,buf_str);       

  l = fill_tcp_data_p(ebuf,l,set3);       
  mac_to_str(buf_str, set.mac[0]);
  l = fill_tcp_data(ebuf,l,buf_str);       

  l = fill_tcp_data_p(ebuf,l,set35);       
  mac_to_str(buf_str, set.mac[1]);
  l = fill_tcp_data(ebuf,l,buf_str);       

  l = fill_tcp_data_p(ebuf,l,set36);       
  mac_to_str(buf_str, set.mac[2]);
  l = fill_tcp_data(ebuf,l,buf_str);       

  l = fill_tcp_data_p(ebuf,l,set37);       
  l = fill_tcp_data(ebuf,l,set.mac_any ? "checked" : "");       

  l = fill_tcp_data_p(ebuf,l,set4);       
  utoa(set.telnet_port, buf_str, 10);
  l = fill_tcp_data(ebuf,l,buf_str);       

  l = fill_tcp_data_p(ebuf,l,set5);       
  ultoa(set.baud_rate, buf_str, 10);
  l = fill_tcp_data(ebuf,l,buf_str);       

  l = fill_tcp_data_p(ebuf,l,set6);       

  state = 2;
  return l;
}

void mac_to_str(char *str, uint8_t *addr)
{
  uint8_t i, v;
  for(i=0; i<6; i++)
  {
    v = (addr[i]>>4)&0x0F; 
    if(v > 9) *str++ = 'A'+v-10;
    else *str++ = '0'+v;
    v = addr[i]&0x0F; 
    if(v > 9) *str++ = 'A'+v-10;
    else *str++ = '0'+v;
  }
  *str = 0;
}

uint8_t str_to_mac(char* str, uint8_t *buf)
{
  uint8_t i, c, v;
  strupr(str);
  for(i=0; i<12; i+=2)
  {
    c = str[i];
    if(c<'0' || c>'F' || (c>'9' && c<'A')) return 0;
    if(c >= 'A') v = c-'A'+10;
    else v = c-'0';
    buf[i/2] = v<<4;

    c = str[i+1];
    if(c<'0' || c>'F' || (c>'9' && c<'A')) return 0;
    if(c >= 'A') v = c-'A'+10;
    else v = c-'0';
    buf[i/2] |= v;
  }
  return 1;
}

void ip_to_str(char *str, uint8_t *addr)
{
  uint8_t i, fl, v;
  for(i=0; i<4; i++)
  {
    fl = 0; v = addr[i];
    if(v >= 100){ fl=1; *str++ = '0' + v/100; v %= 100; }
    if(v>=10 || fl){ *str++ = '0' + v/10; v %= 10; }
    *str++ = '0' + v;
    if(i < 3) *str++ = '.';
  }
  *str = 0;
}

uint8_t str_to_ip(char* str, uint8_t *buf)
{
  uint8_t i, c;
  for(i=0; i<4; i++)
  {
    buf[i] = 0;
    while(1)
    {
      c = *str++;
      if(c == '.') break;
      if(c == 0)
      {
        if(i == 3) return 1;
        else return 0;
      }
      if(c<'0' || c>'9') return 0;
      buf[i] = buf[i]*10 + c-'0';
    }
  }
  return 1;
}

uint8_t str_to_u16(char* str, uint16_t *buf)
{
  uint8_t c;
  *buf = 0;
  while(1)
  {
    c = *str++;
    if(c == 0) break;
    if(c<'0' || c>'9') return 0;
    *buf = *buf*10 + c-'0';
  }
  return 1;
}

uint8_t str_to_u32(char* str, uint32_t *buf)
{
  uint8_t c;
  *buf = 0;
  while(1)
  {
    c = *str++;
    if(c == 0) break;
    if(c<'0' || c>'9') return 0;
    *buf = *buf*10 + c-'0';
  }
  return 1;
}

/*void u16_to_str(char *str, uint16_t v)
{
  uint8_t fl=0;
  if(v >= 10000){ fl=1; *str++ = '0' + v/10000; v %= 10000; }
  if(v>=1000 || fl){ fl=1; *str++ = '0' + v/1000; v %= 1000; }
  if(v>=100 || fl){ fl=1; *str++ = '0' + v/100; v %= 100; }
  if(v>=10 || fl){ *str++ = '0' + v/10; v %= 10; }
  *str++ = '0' + v;
  *str = 0;
}

void u32_to_str(char *str, uint32_t v)
{
  uint8_t fl=0;
  if(v >= 10000){ fl=1; *str++ = '0' + v/10000; v %= 10000; }
  if(v>=1000 || fl){ fl=1; *str++ = '0' + v/1000; v %= 1000; }
  if(v>=100 || fl){ fl=1; *str++ = '0' + v/100; v %= 100; }
  if(v>=10 || fl){ *str++ = '0' + v/10; v %= 10; }
  *str++ = '0' + v;
  *str = 0;
}*/


//-------------------------------------------------------------------------------------------------
uint16_t http(uint8_t *buf, uint16_t len)
{
    char* p=(char*)&buf[len];
    len = 0;


    // GET
    if(str_cmp(&p[0], "GET /", 5))
    {
      // GET / HTTP - send login page
      if(str_cmp(&p[5], " HTTP", 5))
      { 
        //len = fill_tcp_data_p(buf,0,head);
        //len = fill_tcp_data_p(buf,len,login);
        //return len;
        len = send_login(buf);
      }

      // GET /log?pass=123&submit=Enter - send settings page
      else if(str_cmp(&p[5], "log", 3)) 
      {
        if(state && str_cmp(&p[14], set.password, strlen(set.password)))
        {
          len = send_set(buf);
        }
        else
        {
          //len = fill_tcp_data_p(buf,0,head);
          //len = fill_tcp_data_p(buf,len,login);
          len = send_login(buf);
        }
      }

      // GET /set?mac=000102030405
      //  &ipaddr=192.168.1.19&mac1=112233445566&mac2=223344556677&mac3=334455667788
      //  &port=23&baud=38400&pass1=&pass2=&submit=Save+settings 
      else if(str_cmp(&p[5], "set", 3)) 
      {
        if(state == 2)
        {
          uint8_t fl=0, n;

          fl = 0;
          // check MAC
          n = find_param(p, "mac", buf_str);
          if(n != 12) fl |= 1;
          if(!str_to_mac(buf_str, new.mac_addr)) fl |= 1;

          // check IP
          n = find_param(p, "ipaddr", buf_str);
          if(n < 7) fl |= 2;
          if(!str_to_ip(buf_str, new.ip_addr)) fl |= 2;

          // check MAC1
          n = find_param(p, "mac1", buf_str);
          if(n != 12) fl |= 1;
          if(!str_to_mac(buf_str, new.mac[0])) fl |= 1;

          // check MAC2
          n = find_param(p, "mac2", buf_str);
          if(n != 12) fl |= 1;
          if(!str_to_mac(buf_str, new.mac[1])) fl |= 1;

          // check MAC3
          n = find_param(p, "mac3", buf_str);
          if(n != 12) fl |= 1;
          if(!str_to_mac(buf_str, new.mac[2])) fl |= 1;

          // check Any MAC
          n = find_param(p, "any_", buf_str);
          if(n == 0) new.mac_any = 0;
          else       new.mac_any = 1;
          //if(buf_str[0]=='o' && buf_str[1]=='n') new.mac_any = 1;
          //else                                   new.mac_any = 0;

          // check mask
          /*n = find_param(p, "mask", buf_str);
          if(n < 7) fl |= 4;
          if(!str_to_ip(buf_str, new.ip_mask)) fl |= 4;

          // check gateway
          n = find_param(p, "gw", buf_str);
          if(n < 7) fl |= 4;
          if(!str_to_ip(buf_str, new.ip_gw)) fl |= 4;*/

          // check port
          n = find_param(p, "port", buf_str);
          if(n < 1) fl |= 8;
          if(!str_to_u16(buf_str, &new.telnet_port)) fl |= 4;

          // check baud
          n = find_param(p, "baud", buf_str);
          if(n < 1) fl |= 16;
          if(!str_to_u32(buf_str, &new.baud_rate)) fl |= 16;

          // check passwords
          n = find_param(p, "pass1", new.password);
          if(find_param(p, "pass2", buf_str) != n) fl |= 32;
          if(str_cmp(new.password, buf_str, n) == 0) fl |= 32;

          // not correct
          if(fl)
          {
            //putstrln("*NOT CORRECT");
            len = send_set(buf);
          }

          // ALL OK (or not)
          else
          {
            len = fill_tcp_data_p(ebuf,0,head);       
            len = fill_tcp_data_p(ebuf,len,saved);       

            //putstrln("*sending saved");  
            //start_send(buf, l);

            state = 0;
            update_ee(&new);
          }
        }

        else
        {
          //len = fill_tcp_data_p(buf,0,head);
          //len = fill_tcp_data_p(buf,len,login);
          //return len;
          len = send_login(buf);
        }
      }

    }

    else
    {
                        // head, post and other methods:
      len=http200ok();
      len=fill_tcp_data_p(ebuf,len,PSTR("<h1>200 OK</h1>"));

    }

  return len;

}
//-------------------------------------------------------------------------------------------------
