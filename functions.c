#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// struktura RR
#ifndef FUNCTIONS_H
#include "functions.h"
#endif

// over jestli se jedna o validni ip adresu
// @ret true platna adresa
// @ret false neplatna adresa
bool validate_ip(char *ip, bool *v6, bool six_on) {
	char buffer[16];
	if(!six_on && inet_pton(AF_INET, ip, buffer)) { // platna ipv4 adresa a zaroven nevyzadujeme ipv6
		return true;
	}
	else if(six_on && inet_pton(AF_INET6, ip, buffer)) { // platna ipv6 adresa a zaroven chceme ipv6
		return true;
	}
	return false; // pokud zada jako server ipv4 a chce ipv6 nebo pokud zada server ipv6 a chce ipv4
}

// over zda se jedna o validni port
// @ret int cislo portu
// @ret -1 nevalidni port
int validate_port(char *port) {
    char *ptr;
    long ret;
    ret = strtol(port, &ptr, 10);
    if(strlen(ptr)) // vlozena i nejaka pismenka
        return -1;
    if(ret < 0 || ret > 65535) // neodpovida range
        return -1;
    return (int)ret;
}

// over domenove jmeno
// funkce inspirovana z: http://man7.org/linux/man-pages/man3/getaddrinfo.3.html?fbclid=IwAR1nM16wJIbbV9qvZ6yES__aYIfzpN63QYpDA53Ce6t425TGtsAxvzpeu60
void validate_hostname(char *hostname, bool six_on) {

	int sfd; // docket
    struct addrinfo hints, *infoptr, *rp;
    memset(&hints, 0, sizeof(hints));

	if(six_on) { // -6
    	hints.ai_family = AF_INET6;
    }
    else {
    	hints.ai_family = AF_INET;
    }
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    int result = getaddrinfo(hostname, NULL, &hints, &infoptr); // ziskani seznamu ip adres
    if (result) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(1); // protoze jsme v main nic nealokovali, muzeme pouzit bez obav exit()
    }

	bool f = false; // nalezena funkcni adresa
	char ip[256]; // buffer pro ip adresu
	memset(ip, '\0', 256);

    for (rp = infoptr; rp != NULL; rp = rp->ai_next) { // overuj adresy, dokud se nedostanes k funkcni

        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); // socket pro overeni funkcnosti adresy
        if (sfd == -1)
            continue;
			
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) { // podarilo se navazat spojeni s jednou z adres
            getnameinfo(rp->ai_addr, rp->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST); // uloz adresu do bufferu
            f = true; // adresa nalezena
            close(sfd); // zavri socket
			break;
        }
		close(sfd); // zavri socket
    }

    if (!f) { // nebyly nalezeny zadne adresy k domenovemu jmenu
        fprintf(stderr, "Nelze navazat spojeni s hostname.\n");
        exit(1);
    }

	freeaddrinfo(infoptr); // uvolni systemove alokovany buffer
	
	memset(hostname,'\0',256);
    strcpy(hostname,ip); // prepis hostname na ip adresu
}

// over jestli je hledana adresa validni retezec
void validate_string(char *url) {

	if(strlen(url) < 3 || strlen(url) > 255) // nevyhovuje delka adresy
		goto fail;

	if(url[strlen(url)-1] == '.') // pokud je posledni znak tecka, nech ji zmizet
		url[strlen(url)-1] = '\0';

	if(url[0] == '.' || url[0] == '-' || url[strlen(url)-1] == '-')
		goto fail; // vyrad adresy ktere zacinaji nebo konci spatnym znakem

	int label_c = 0; // pocet znaku jednoho labelu

	for(int i = 0; i < strlen(url); i++) {
		label_c++; // pridat znak do labelu

		if(!isalnum(url[i]) && url[i] != '-' && url[i] != '.')
			goto fail; // vyrad adresy ktere obsahuji spatne znaky

		if(url[i] == '.') {
			label_c = 0; // preruseni labelu
			if(url[i+1] == '.' || url[i+1] == '-')
				goto fail; // po tecce nesmi nasledovat - ani .
		}

		else if(url[i] == '-') {
			if(url[i+1] == '.')
				goto fail; // po - nesmi byt .
		}

		if(label_c == 64)
			goto fail; // label ma vice nez 63 znaku
	}
	return;

	fail:
	    fprintf(stderr, "Pozadovana adresa neni validni.\n");
        exit(1); // protoze jsme v main nic nealokovali, muzeme pouzit bez obav exit()

}

// INSPIROVANO Z: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
// prevod retezce s domenou na dns format
void dns_format(unsigned char* dns, char* host) {
	int lock = 0;
	
    strcat((char*)host,".");
    for(int i = 0; i < strlen((char*)host); i++) {
        if(host[i]=='.') {
            *dns++ = i-lock;
            for(;lock<i;lock++) {
                *dns++=host[lock];
            }
            lock++;
        }
    }
    *dns++='\0';
}

// INSPIRACE pouziti offsetu: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
// parsovani stringu, ktery je soucasti dns datagramu
void parser(unsigned char *result, unsigned char* pos, unsigned char* dgram, int* stuck) {
 
 	memset(result,'\0',256);
    
    int c = 0; // counter zapisu do bufferu
    bool off = false; // jestli obsahuje offset
    int offset; // pozice offsetu
 
    *stuck = 1; // delka retezce
 
    while(*pos != 0) { // dokud nenarazi na konec question name
    
        if(*pos >= 192) { // nastavene nejvyssi dva bity, je to pointer
            offset = (*pos) * 256 + *(pos+1) - 49152; // 49152 ma nastavene nejvyssi bity: 1100000000000000, ty pomoci odecteni odstrani bity v pozici kam ukazuje pointer
            pos = dgram + offset - 1; // vypocitej presnou pozici
            off = true; // preskocime pomoci ukazatele jinam
        }
     	else { // znak, uloz a pokracuj
            result[c] = *pos;
			c++;
 		}
 		
        pos += 1; // posun se v retezci
 
        if(!off) { // nedoslo k vyskytu ukazatele
            *stuck += 1; // posun se dal v datagramu
    	}
    }
 
    if(off) { // doslo k vyskytu ukazatele
        *stuck += 1; // posun se o znak dal v datagramu
	}

 	int i = 0; // citac formatovani adresy
    while(i < strlen((const char *)result)) {
        c = result[i]; // vezmi cislo na zacatku labelu
        for(int j = 0; j < c; j++) {
            result[i] = result[i+1]; // nacti do result spravny pocet znaku labelu
            i++;
        }
        result[i]='.'; // pridej tecku
        i++; // prejdi na dalsi label
    }
    //result[i-1]='\0'; // smaz posledni tecku
}

// vytiskni odpovedi na vystup
// @ret 0 v poradku
// @ret 1 chyba
int print_answers(int cnt, int *size, unsigned char *dgram, int *pos, unsigned char *position, unsigned char *content, char *cl, char *tp, char *typ) {

	printf("%s (%i)\n",typ,cnt);

	if(cnt) { // existuji nejake odpovedi

		for(int i = 0; i < cnt; i++) { // naparsuj postupne kazdou odpoved

			// promenne pro typ a tridu odpovedi
			memset(tp,'\0',6);
			memset(cl,'\0',3);
		
			position = (unsigned char *)&dgram[*size]; // nastav pozici za question blok	
		
			parser(content, position, dgram, pos); // uloz retezec Rname
			(*size) += (*pos); // pricti delku retezce Rname
			RR *rr = (RR *)&dgram[*size]; // struktura odpovedi

			// naparsuj tridu
			if(ntohs(rr->cl) == 1) {
				strcpy(cl,"IN");
			}
			else if(ntohs(rr->cl) == 2) {
				strcpy(cl,"CS");
			}
			else if(ntohs(rr->cl) == 3) {
				strcpy(cl,"CH");
			}
			else if(ntohs(rr->cl) == 4) {
				strcpy(cl,"HS");
			}
			else {
				strcpy(cl,"???");
			}

			// naparsuj typ
			if(ntohs(rr->type) == 1) {
				strcpy(tp,"A");
			}
			else if(ntohs(rr->type) == 2) {
				strcpy(tp,"NS");
			}
			else if(ntohs(rr->type) == 3) {
				strcpy(tp,"MD");
			}
			else if(ntohs(rr->type) == 4) {
				strcpy(tp,"MF");
			}						
			else if(ntohs(rr->type) == 5) {
				strcpy(tp,"CNAME");
			}
			else if(ntohs(rr->type) == 6) {
				strcpy(tp,"SOA");
			}
			else if(ntohs(rr->type) == 7) {
				strcpy(tp,"MB");
			}
			else if(ntohs(rr->type) == 8) {
				strcpy(tp,"MG");
			}	
			else if(ntohs(rr->type) == 9) {
				strcpy(tp,"MR");
			}
			else if(ntohs(rr->type) == 10) {
				strcpy(tp,"NULL");
			}
			else if(ntohs(rr->type) == 11) {
				strcpy(tp,"WKS");
			}
			else if(ntohs(rr->type) == 12) {
				strcpy(tp,"PTR");
			}	
			else if(ntohs(rr->type) == 13) {
				strcpy(tp,"HINFO");
			}
			else if(ntohs(rr->type) == 14) {
				strcpy(tp,"MINFO");
			}
			else if(ntohs(rr->type) == 15) {
				strcpy(tp,"MX");
			}
			else if(ntohs(rr->type) == 16) {
				strcpy(tp,"TXT");
			}	
			else if(ntohs(rr->type) == 28) {
				strcpy(tp,"AAAA");
			}
			else {
				strcpy(tp,"???");
			}
			
			printf("%s\t%s\t%s\t%d\t", content, cl, tp, htonl(rr->ttl));
			
			*size += sizeof(RR); // skoc za strukturu
			position = (unsigned char *)&dgram[*size]; // nastav pozici pred Rdata
			
			// VYPSANI ODPOVEDI
			// kompletne podporovane: CNAME / A / AAAA / NS / PTR / SOA / TXT
			// podpora vypisu hex dat: jakekoliv dalsi zaznamy
			
			if(ntohs(rr->type) == 5 || ntohs(rr->type) == 2 || ntohs(rr->type) == 12 || ntohs(rr->type) == 6 || ntohs(rr->type) == 16) { // CNAME / A / AAAA / NS / PTR / SOA / TXT
				parser(content, position, dgram, pos); // naparsuj Rdata
				printf("%s",content);
			}
			else if(ntohs(rr->type) == 1) { // A zaznam
				if(ntohs(rr->rdlen) != 4) { // delka neni 4
					fprintf(stderr,"Chybna delka dat v odpovedi.\n");
					return 1;
				}
				memset(content, '\0', 256); // vynuluj buffer
				memcpy(content, position, 4); // zkopiruj ip adresu do bufferu							
				for(int i = 0; i < 4; i++) {
					printf("%i",content[i]);
					if(i != 3)
						printf(".");
				}         											
			}
			else if(ntohs(rr->type) == 28) { // AAAA zaznam
			
				if(ntohs(rr->rdlen) != 16) { // delka neni 16
					fprintf(stderr,"Chybna delka dat v odpovedi.\n");
					return 1;
				}
			
				memset(content, '\0', 256); // vynuluj buffer
				memcpy(content, position, 16); // zkopiruj ip adresu do bufferu							
				
				for(int i = 0; i < 16; i++) {
					printf("%02x",content[i]);
					if(i % 2 && i != 15)
						printf(":");
				}         											
			}	
			else { // ostatni typy jako HEX
				for(int i = 0; i < ntohs(rr->rdlen); i++) {
					printf("%X", position[i]);
				}
			}
								
			printf("\n");
			
			*size += ntohs(rr->rdlen); // preskoc Rdata a pokracuj dal
		}	
		
		printf("\n"); // zadne dalsi odpovedi
	}	
	
	return 0;		

}

// over jestli se jedna o validni ip adresu a zaroven ji preved do formatu na reverzni dotaz
// @ret true validni
// @ret false nevalidni
bool revert_ip(char *ip, bool six_on) {
	
	struct sockaddr_in sa; // ipv4
	struct in6_addr sa6; // ipv6

	if(!six_on && inet_pton(AF_INET, ip, &(sa.sin_addr))) { // validni ipv4 adresa
		int a,b,c,d;
		sscanf(ip,"%d.%d.%d.%d",&a,&b,&c,&d);
		sprintf(ip, "%d.%d.%d.%d", d, c, b, a);
		strcat(ip,".in-addr.arpa");	
		return true;
	}
	
	if(six_on && inet_pton(AF_INET6, ip, &sa6)) { // validni ipv6 adresa
	
  		sprintf(ip,"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                 		(int)sa6.s6_addr[0], (int)sa6.s6_addr[1],
                 		(int)sa6.s6_addr[2], (int)sa6.s6_addr[3],
                 		(int)sa6.s6_addr[4], (int)sa6.s6_addr[5],
                 		(int)sa6.s6_addr[6], (int)sa6.s6_addr[7],
                 		(int)sa6.s6_addr[8], (int)sa6.s6_addr[9],
                 		(int)sa6.s6_addr[10], (int)sa6.s6_addr[11],
                 		(int)sa6.s6_addr[12], (int)sa6.s6_addr[13],
                 		(int)sa6.s6_addr[14], (int)sa6.s6_addr[15]);		
		char result[256];
		memset(result,'\0',256);		
		int j = 0;
		for(int i = 31; i >= 0; i--) { // otoc poradi a pridavej tecky za kazdy byte
			result[j] = ip[i];
			j++;
			result[j] = '.';
			j++;
		}		
		memset(ip,'\0',256);
		strcpy(ip,result);		
		strcat(ip,"ip6.arpa");	
		return true;	
	}
	return false;	
}
