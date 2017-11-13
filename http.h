#ifndef _HTTP_H_
#define _HTTP_H_

//void http(void);
uint16_t http(uint8_t *buf, uint16_t len);
void mac_to_str(char *str, uint8_t *addr);
void ip_to_str(char *str, uint8_t *addr);

#endif