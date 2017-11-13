#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <avr/io.h>
#include <avr/eeprom.h>
#include <avr/wdt.h>
#include <util/delay.h>
#include <avr/interrupt.h>

#include "eth/ip_arp_udp_tcp.h"
#include "eth/net.h"
#include "eth/enc28j60.h"

#include "main.h"
#include "fifo.h"
#include "http.h"

// global packet buffer
#define BUFFER_SIZE 1100
uint8_t ebuf[BUFFER_SIZE+1];

//uint8_t http_f=0;
extern uint8_t ready, connected;

SET_T set;
SET_T set_def=
{
    .mac_addr = {DEF_MAC0, DEF_MAC1, DEF_MAC2, DEF_MAC3, DEF_MAC4, DEF_MAC5},
    .ip_addr = {DEF_IP0, DEF_IP1, DEF_IP2, DEF_IP3},
    .mac[0] = {DEF_MAC10, DEF_MAC11, DEF_MAC12, DEF_MAC13, DEF_MAC14, DEF_MAC15},
    .mac[1] = {DEF_MAC20, DEF_MAC21, DEF_MAC22, DEF_MAC23, DEF_MAC24, DEF_MAC25},
    .mac[2] = {DEF_MAC30, DEF_MAC31, DEF_MAC32, DEF_MAC33, DEF_MAC34, DEF_MAC35},
    .mac_any = 1,
    .telnet_port = DEF_PORT,
    .baud_rate = DEF_BAUD,
    .password = DEF_PASSWORD
};
SET_T EEMEM ee;

volatile uint8_t in_buf[IN_SIZE]; // ->UART->telnet
FIFO in_fifo;


void update_ee(SET_T *s)
{
    eeprom_update_block((const void *)s, &ee, sizeof(SET_T));
}

ISR(USART_RX_vect)
{
    uint8_t b = UDR0;

    fifo_push(&in_fifo, b);

#ifdef RTSCTS
    if((in_fifo.size - in_fifo.full) < 5)
    {
        PORTC |= (1<<PORTC5); // Set CTS to 1 (NOT ready for receive next data)
	}
#elseif RTSCTSJUMPER
    if((in_fifo.size - in_fifo.full) < 5)
	{
		if (PIND&_BV(PD2)) // if PD2 is High then...
		{
			PORTC |= (1<<PORTC5); // Set CTS to 1 (NOT ready for receive next data)
		}
    }
#endif    
}

volatile uint8_t timer_flag;
ISR(TIMER1_COMPA_vect)
{
    timer_flag = 1;
}

int main(void)
{
    uint16_t dat_p;

    fifo_init(&in_fifo, (uint8_t*)in_buf, IN_SIZE);

    DDRD &= ~_BV(PD2); // Set PD2 as input for RTSCTSJUMPER (see make file)

    DDRB = 3;
    DDRC = 37; // Status pin - connected telnet or not   BIN 00100101   PC0 - CONNECT, PC2 - RESET ENC..., PC5 - CTS
    DDRD = _BV(PD7);

    PORTC = _BV(PC3) | _BV(PC1); // pullup for ftp/http button & "reset EE button"

    PORTC |= (1<<PORTC2); // ENC reset off
    _delay_ms(200);
    PORTC &= ~(1<<PORTC2); // ENC reset on
    _delay_ms(200);
    PORTC |= (1<<PORTC2); // ENC reset off
    _delay_ms(200);

    //--- read settings ---
    eeprom_read_block((void *)&set, &ee, sizeof(SET_T));

    if(set.password[0]==255 || (PINC&_BV(PC1))==0) // invalid EE data or reset pressed
    {
        memcpy(&set, &set_def, sizeof(SET_T));
        eeprom_update_block((const void *)&set, &ee, sizeof(SET_T));
    }

    //--- USART ---
    uint32_t ubrr = F_CPU/16/set.baud_rate - 1;
    UBRR0H = (uint8_t)(ubrr>>8);
    UBRR0L = (uint8_t)ubrr;  
    UCSR0B = _BV(RXCIE0) | //_BV(TXCIE0) | // RX, TX complete interrupts
    _BV(RXEN0) | _BV(TXEN0); // RX, TX enable
    UCSR0C = _BV(UCSZ01) | _BV(UCSZ00); // 8-bit data

    //--- TIMER1 ---
    uint32_t ocr = F_CPU/8/100-1; // 100 Hz timer
    OCR1AH = (uint8_t)(ocr>>8);
    OCR1AL = (uint8_t)ocr;
    TCCR1B = _BV(WGM12) | _BV(CS11); // CTC OCR1A, clk/8
    TIMSK1 = _BV(OCIE1A); // timer interrupt enable

    //--- initialize the hardware driver for the enc28j60 ---
    enc28j60Init(set.mac_addr);
    enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
    _delay_loop_1(0); // 60us
    enc28j60PhyWrite(PHLCON,0x476);

    any_mac = set.mac_any;
    memcpy(macs, set.mac, 3*6);
    //init the ethernet/ip layer:
    init_mac_ip(set.mac_addr, set.ip_addr);

    www_server_start(80);
    telnet_server_start(set.telnet_port);

    UDR0 = '>';

    sei();

    while(1)
    {
        if(connected)
        {
            PORTC |= _BV(PC0);
        }
        else
        {
            PORTC &= ~_BV(PC0);
            fifo_init(&in_fifo, (uint8_t*)in_buf, IN_SIZE);
        }

        uint16_t len;
        uint8_t type;
        // read packet, handle ping and wait for a tcp packet:
        dat_p = packetloop_arp_icmp_tcp(ebuf, enc28j60PacketReceive(BUFFER_SIZE, ebuf), &len, &type);

        // there is data from ethernet
        if(dat_p)
        {
            PORTB |= 2;

            if(type == 1) // WWW
            {
                dat_p = http(ebuf, dat_p); // process http request & prepare answer
                www_server_reply(ebuf, dat_p); // send web page data data back
            }

            else if(type==2 && connected) // telnet
            {

                uint8_t *ptr = &ebuf[dat_p];
                while(len--)
                {
#ifdef RTSCTS
                    while(!(UCSR0A&_BV(UDRE0)) || (PINC&_BV(PC4))); // check RTS pin 
#elseif RTSCTSJUMPER
                    if (PIND&_BV(PD2)) // if PD2 is High then...
                    {
                        while(!(UCSR0A&_BV(UDRE0)) || (PINC&_BV(PC4))); // check RTS pin 
                    }
                    else // if PD2 low then...
                    {
                        while(!(UCSR0A&_BV(UDRE0))); // without check RTS pin    
                    }
#else
                    while(!(UCSR0A&_BV(UDRE0))); // without check RTS pin    
#endif    
                    UDR0 = *ptr++;  
                } 

            }
            
            PORTB &= ~2;
        }

        // there is no data from ethernet
        else 
        {  
            // send somthing to ethernet if any on timer
            if(timer_flag && ready && connected)
            {
                timer_flag = 0;
                cli();
                uint8_t s = fifo_pop(&in_fifo, &ebuf[TCP_CHECKSUM_L_P+3]);
                sei();
                if(s)
                {
                    telnet_server_send(ebuf, s);
                }
#ifdef RTSCTS                  
                PORTC &= ~(1<<PORTC5); // Set CTS to 0 (Ready for receive)
#elseif RTSCTSJUMPER
				if (PIND&_BV(PD2)) // if PD2 is High then...
				{
	                PORTC &= ~(1<<PORTC5); // Set CTS to 0 (Ready for receive)
				}
#endif            
            } 
        }
    }

    return 0;
}

