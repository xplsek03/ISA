#include <stdbool.h>

bool validate_ip(char *ip, bool *v6); // over ip adresu
int validate_port(char *port); // over port
void validate_hostname(char *hostname); // over server
void validate_string(char *url); // over dom. jmeno
void dns_format(unsigned char* dns,char* host); // adresa->dns format
void parser(unsigned char *result, unsigned char* pos, unsigned char* dgram, int* zarazka); // naparsuj libovolny retezec name z dns datagramu

typedef struct header { // dns hlavicka
	unsigned short id; // id k rozpoznani request-answer
	unsigned short guts; // qr/opcode/aa/tc/rd/ra/z/rcode
	unsigned short qcount; // pocet quest
	unsigned short acount; // pocet answ
	unsigned short aucount; // pocet auth answ
	unsigned short addcount; // pocet addit answ
	
} HEADER;

typedef struct q { // dns query
	unsigned short type;
	unsigned short cl;
} Q;

// je tu kvuli zmizeni paddingu u struktur, RR 12B->10B
#pragma pack(push, 1)
typedef struct rr { // dns resource record
	unsigned short type;
	unsigned short cl;
	unsigned int ttl;
	unsigned short rdlen; // delka rdata v bytech
} RR;
#pragma pack(pop)

bool revert_ip(char *ip); // adresa do rDNS formatu
int print_answers(int cnt, int *size, unsigned char *dgram, int *pos, unsigned char *position, unsigned char *content, char *cl, char *tp, char *typ); // tisk odpovedi na vystup
