#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>

#include "functions.h"

int main (int argc, char **argv) {

	// flagy
	bool r_on = false; // recurse
	bool x_on = false; // reverse
	bool six_on = false; // ipv6
	bool s_on = false; // server musi byt zadany
	bool v6 = false; // pokud se ma pouzit ipv6 adresa pro odeslani (-s)

	// hodnoty
	int p_val; // cilova hodnota portu jako int
	char s_val[256]; // server
	char p_val_str[6]; // port
	memset(p_val_str,'\0',6);
	strcpy(p_val_str,"53");	
	char ip_val[256]; // dotazovana adresa
	memset(ip_val,'\0',256);
	
	// countery getopt
	int index;
	int c;
	
	opterr = 0;

	if(argc >= 4 && argc <= 9) { // argumentu je spravny pocet

		// https://www.gnu.org/software/libc/manual/html_node/Example-of-Getopt.html#Example-of-Getopt
		while ((c = getopt(argc, argv, "rx6s:p:")) != -1) {
			switch (c) {
				case 'r':
					r_on = true;
					break;
				case 'x':
					x_on = true;
					break;
				case '6':
					six_on = true;
					break;
				case 's':
					s_on = true;
					strcpy(s_val, optarg);
					break;
				case 'p':
					strcpy(p_val_str, optarg);
					break;
				case '?':
					if (optopt == 'p' || optopt == 's') // chybejici hodnoty
						fprintf (stderr, "U argumentu -%c chybi hodnota.\n", optopt);
					else if (isprint (optopt)) // neni printable
						fprintf (stderr, "Neznamy argument: `-%c'.\n", optopt);
					else // neznama moznost
						fprintf (stderr,"Neznamy argument `\\x%x'.\n",optopt);
					return 1;

				default:
					abort(); // ukonci parsovani
			}
		}
	}

	if(!s_on) { // kdyz chybi server
		fprintf (stderr,"Chybi server argument.\n");
		return 1;
	}

	bool b = false; // pocitadlo zbylych argumentu
	for (index = optind; index < argc; index++) {// projdi argumenty, ktery nebyly explicitne zadane
		if(b) {
			fprintf (stderr,"Nejaky argument prebyva.\n");
			return 1;
		}
		b = true;
		strcpy(ip_val,argv[index]); // uloz query ip adresu
	}

	if(!b) { // chybi ip adresa query
		fprintf (stderr,"Chybi query ip adresa.\n");
		return 1;
	}

	if(x_on) {// zapnuty reverzni dotaz
		if(!revert_ip(ip_val)) { // zvaliduj jestli je to IP adresa a zaroven ji revertuj kvuli rDNS
            fprintf(stderr, "Dotazovana adresa neni IP adresou.\n");
            return 1;
		}
	}
	else { // obycejny dotaz, muze byt dotazovan pouze validni retezec
		validate_string(ip_val);
	}

	p_val = validate_port(p_val_str); // over hodnotu portu
    if(p_val == -1) { // spatne zadany port
        fprintf(stderr, "Port neni spravne zadany.\n");
        return 1;
    }
    
	if(!validate_ip(s_val, &v6)) { // zadany server neni platna ip adresa
		validate_hostname(s_val); // vrat funkcni ip adresu z domenoveho jmena a nahrad za puvodni hostname

		if(!strlen(s_val)) {
			fprintf (stderr,"Nepodarilo se pripojit k zadne IP adrese zadaneho dns serveru.\n");
			return 1;
		}
	}

	// ******** PLNENI DATAGRAMU *********

	int size = 0; // aby nebylo potreba prepocitavat pozici v datagramu
	unsigned char dgram[65536]; // datagram
	HEADER *header = (HEADER *)&dgram;
	header->id = (unsigned short)htons(getpid());
	header->guts = htons(0);
	if(r_on) {
		header->guts ^= 1UL << 0; // POZN: xxxxxxx1  <-(1) xxxxxxxx <-(2)
	}

	header->qcount = htons(1); // jediny pozadavek 
	header->acount = 0;
	header->aucount = 0;
	header->addcount = 0;
	
	size = sizeof(HEADER);
	
	unsigned char *position = (unsigned char *)&dgram[size];
	
	dns_format(position, ip_val); // preved adresu do dns formatu

	// DNS FORMAT SEGFAULT PRO IPV6 ADDR
	
	size += strlen((const char *)position) + 1;

	Q *q = (Q *)&dgram[size];	
	if(x_on) {
		q->type = htons(12); // PTR, reverzni lookup
	}
	else if(six_on) {
		q->type = htons(28); // AAAA
	}
	else {
		q->type = htons(1); // A
	}
	
	q->cl = htons(1); // IN

	size += sizeof(Q);

	// ******** ODESLANI DATAGRAMU *********

	int s; // socket

	if(v6) { // IPv6
    	struct sockaddr_in6 dest; // server socket
    	memset(&dest, 0, sizeof(dest));
    	dest.sin6_family = AF_INET6;
    	dest.sin6_port = htons(p_val); // port
		inet_pton(AF_INET6, s_val, &(dest.sin6_addr)); // ipv6 addr
		
		s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if(s == -1) {
			fprintf(stderr,"Nelze vytvorit socket.\n");
			return 1;
		}
		struct timeval timeout; // timeout socketu
		timeout.tv_sec = 5; // nastav timeout na 5s, kdyby neprisla odpoved 
		if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
			perror("Setsockopt error.\n");
		}
		
		if(sendto(s, dgram, size, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) { // odeslani datagramu
			perror("Chyba pri odesilani dat.\n"); // vystup s kodem na stderr
			return 1;
		}
		int incoming = sizeof(dest);
		if(recvfrom(s,dgram, 65536 , 0, (struct sockaddr*)&dest, (socklen_t*)&incoming) < 0) {
			perror("Chyba pri prijimani dat.\n");
		}
	}
	else { // IPv4
    	struct sockaddr_in dest; // server socket
    	memset(&dest, 0, sizeof(dest));
    	dest.sin_family = AF_INET;
    	dest.sin_addr.s_addr = inet_addr(s_val); // ipv4 adresa
    	dest.sin_port = htons(p_val); // port
    	
		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(s == -1) {
			fprintf(stderr,"Nelze vytvorit socket.\n");
			return 1;
		}
		struct timeval timeout; // timeout socketu
		timeout.tv_sec = 5; // nastav timeout na 5s, kdyby neprisla odpoved 
		if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
			perror("Setsockopt error.\n");
		}
		
		if(sendto(s, dgram, size, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) { // odeslani datagramu
			perror("Chyba pri odesilani dat.\n"); // vystup s kodem na stderr
			return 1;
		}
		int incoming = sizeof(dest);
		if(recvfrom(s,dgram, 65536 , 0, (struct sockaddr*)&dest, (socklen_t*)&incoming) < 0) {
			perror("Chyba pri prijimani dat.\n");
		}
	}
    
	
    // ******** ZPRACOVANI ODPOVEDI *********

	header = (HEADER *)&dgram;

	if(header->id == htons(getpid()) && ((htons(header->guts) >> 15) & 1U)) { // id dotazu odpovida id odpovedi a je to odpoved

		if(r_on && !((htons(header->guts) >> 15) & 1U)) { // pokud chceme rekurzi a neni dostupna, vyhod chybu
			fprintf(stderr,"Rekurze neni na tomto serveru dostupna.\n");
			return 1;
		}
		
		if(((htons(header->guts) >> 0) & 1U) || ((htons(header->guts) >> 1) & 1U) 
		|| ((htons(header->guts) >> 2) & 1U) || ((htons(header->guts) >> 3) & 1U)) { // pokud se vyskytla nejaka chyba
		
			if(((htons(header->guts) >> 0) & 1U) && !((htons(header->guts) >> 1) & 1U) 
			&& !((htons(header->guts) >> 2) & 1U) && !((htons(header->guts) >> 3) & 1U)) {
				fprintf(stderr,"Server nedokaze vyhodnotit pozadavek.\n");
				return 1;
			}
			else if(!((htons(header->guts) >> 0) & 1U) && ((htons(header->guts) >> 1) & 1U) 
			&& !((htons(header->guts) >> 2) & 1U) && !((htons(header->guts) >> 3) & 1U)) {
				fprintf(stderr,"Server se nemuze pripojit k nameserveru.\n");
				return 1;
			}

			else if(((htons(header->guts) >> 0) & 1U) && ((htons(header->guts) >> 1) & 1U) 
			&& !((htons(header->guts) >> 2) & 1U) && !((htons(header->guts) >> 3) & 1U)) {
				fprintf(stderr,"Domenove jmeno neexistuje.\n");
				return 1;
			}				

			else if(!((htons(header->guts) >> 0) & 1U) && !((htons(header->guts) >> 1) & 1U) 
			&& ((htons(header->guts) >> 2) & 1U) && !((htons(header->guts) >> 3) & 1U)) {
				fprintf(stderr,"Server tento typ pozadavku neimplementuje.\n");
				return 1;
			}	

			else if(((htons(header->guts) >> 0) & 1U) && !((htons(header->guts) >> 1) & 1U) 
			&& ((htons(header->guts) >> 2) & 1U) && !((htons(header->guts) >> 3) & 1U)) {
				fprintf(stderr,"Server pozadavek zamitnul.\n");
				return 1;
			}	
			else {
				fprintf(stderr,"Neznama chyba.\n");
				return 1;
			}
		}

		printf("AUTORITA\t%s\n", ((htons(header->guts) >> 10) & 1U) ? "ano" : "ne"); // AA bit set
		printf("ZKRACENO\t%s\n", ((htons(header->guts) >> 9) & 1U) ? "ano" : "ne"); // TC bit set
		printf("REKURZE \t%s\n", (((htons(header->guts) >> 7) & 1U) && ((htons(header->guts) >> 8) & 1U)) ? "ano" : "ne");
		// rekurzivni pouze v pripade, ze byla pozadovana rekurze a zaroven je nastavena rekurze dostupna na serveru
	
		printf("\n");
		
		if(ntohs(header->qcount) == 1) { // ptali jsme se na jedinou otazku
			
			size = sizeof(HEADER); // parsovani zacina za hlavickou
			position = (unsigned char *)&dgram[size]; // ukazatel na zacatek question retezce
		
			unsigned char content[256]; // buffer pro vysledek parsovani
			memset(content,'\0',256);
			
			int pos = 0; // zarazka, kde skoncilo parsovani	
							
			parser(content, position, dgram, &pos); // naparsuj question name
			
			size += pos; // dostan se za question name
			
			// naparsovani quesiton class a question type
			q = (Q *)&dgram[size];
			
			// promenne k parsovani odpovedi
			char tp[6];
			memset(tp,'\0',6);
			char cl[3];
			memset(cl,'\0',3);
			
			if(ntohs(q->cl) == 1) {
				strcpy(cl,"IN");
			}
			else if(ntohs(q->cl) == 3) {
				strcpy(cl,"CH");
			}
			else if(ntohs(q->cl) == 4) {
				strcpy(cl,"HS");
			}
			else {
				fprintf(stderr,"Nepodporovana trida question.\n");
				return 1;
			}
			
			if(ntohs(q->type) == 1) {
				strcpy(tp,"A");
			}
			else if(ntohs(q->type) == 12) {
				strcpy(tp,"PTR");
			}				
			else if(ntohs(q->type) == 28) {
				strcpy(tp,"AAAA");
			}
			else {
				fprintf(stderr,"Nepodporovany typ question: %i.\n",ntohs(q->type));
				return 1;
			}							
			
			printf("QUESTION\n%s\t%s\t%s\n", content, cl, tp);
			printf("\n");
							
			size += sizeof(Q); // preskoc question blok
			
			if(print_answers(ntohs(header->acount), &size, dgram, &pos, position, content, cl, tp, "ANSWERS"))
				return 1; // neco bylo spatne naformatovane		

			if(print_answers(ntohs(header->aucount), &size, dgram, &pos, position, content, cl, tp, "AUTHORITATIVE ANSWERS"))
				return 1; // neco bylo spatne naformatovane		

			if(print_answers(ntohs(header->addcount), &size, dgram, &pos, position, content, cl, tp, "ADDITIONAL ANSWERS"))
				return 1; // neco bylo spatne naformatovane					
		}
			
		else { // pokud neobsahuje question
			fprintf(stderr,"Datagram neobsahuje dotaz nebo je vic nez 1.\n");
			return 1;
		}     	
    }
     
	
	return 0;	
	
}
