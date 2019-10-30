#include <stdbool.h>

bool validate_ip(char *ip); // over ip adresu
int validate_port(char *port); // over port
char *validate_hostname(char *hostname); // over server
void validate_string(char *url); // over dom. jmeno
void dns_format(unsigned char* dns,char* host); // adresa->dns format
void parser(unsigned char *result, unsigned char* pos, unsigned char* dgram, int* zarazka);

typedef struct header { // dns hlavicka
	unsigned short id; // id k rozpoznani request-answer
	unsigned short guts; // qr/opcode/aa/tc/rd/ra/z/rcode
	unsigned short qcount; // c: query structs
	unsigned short acount; // c: rr struct
	unsigned short aucount; // c: rr struct
	unsigned short addcount; // c: rr struct
	
} HEADER;

typedef struct q { // dns query
	unsigned short type; // zajima nas 1=A, 5=CNAME
	unsigned short cl; // zajima nas 1=IN(ternet)
} Q;

#pragma pack(push, 1)
typedef struct rr { // dns resource record
	unsigned short type; // zajima nas 1=A, 5=CNAME
	unsigned short cl; // zajima nas 1=IN(ternet)
	unsigned int ttl; // time to live
	unsigned short rdlen; // delka rdata v bytech
	// + RDATA: 32b v4 nebo v6 16*oktet
} RR;
#pragma pack(pop)

bool revert_ip(char *ip);
int print_answers(int cnt, int *size, unsigned char *dgram, int *pos, unsigned char *position, unsigned char *content, char *cl, char *tp, char *typ);
