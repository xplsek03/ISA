#include <stdbool.h>

bool validate_ip(char *ip); // over ip adresu
int validate_port(char *port); // over port
char *validate_hostname(char *hostname); // over server
void validate_string(char *url); // over dom. jmeno
void dns_format(unsigned char* dns,unsigned char* host); // adresa->dns format
void reverse_dns(char *hostname); // -x volba, tisk

typedef struct header { // dns hlavicka
	unsigned short id; // id k rozpoznani request-answer
	unsigned char qr : 1; // 0=req, 1=response
	unsigned char opcode : 4; // req: 0 = query, 1 = inverse query, jinak asi nic
	unsigned char aa : 1; // answ: jeslti odpovida autoritativni server
	unsigned char tc : 1; // answ: truncated, budeme se k tomu chovat jako ze to nepodporujeme :)
	unsigned char rd : 1; // req: chceme rekurzi
	unsigned char ra : 1; // answ: rekurze dostupna
	unsigned char z : 1;
	unsigned char ad : 1;
	unsigned char cd : 1;
	unsigned char rcode : 4; // answ: navratovej kod
	// 16b polozky, jen pocet
	unsigned short qcount; // c: query structs
	unsigned short acount; // c: rr struct
	unsigned short aucount; // c: rr struct
	unsigned short addcount; // c: rr struct
	
} HEADER;

typedef struct q { // dns query
	unsigned short type; // zajima nas 1=A, 5=CNAME
	unsigned short cl; // zajima nas 1=IN(ternet)
} Q;

typedef struct rr { // dns resource record
	unsigned short type; // zajima nas 1=A, 5=CNAME
	unsigned short cl; // zajima nas 1=IN(ternet)
	unsigned int ttl; // time to live
	unsigned short rdlength; // delka rdata v bytech
	// + RDATA: 32b v4 nebo v6 16*oktet
} RR;
