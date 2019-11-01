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

#include "functions.h" // kvuli strukture

int main (int argc, char **argv) {

	// flagy argumentu
	bool r_on = false; // -r
	bool x_on = false; // -x
	bool six_on = false; // -6
	bool s_on = false; // -s
	bool v6 = false; // pokud se ma pouzit ipv6 adresa pro odeslani (zadana -s jako ipv6)

	// hodnoty argumentu
	int p_val; // cilova hodnota portu jako int
	char s_val[256]; // server
	char p_val_str[6]; // port jako string
	memset(p_val_str,'\0',6);
	strcpy(p_val_str,"53");	// uloz defaultni port
	char ip_val[256]; // dotazovana adresa
	memset(ip_val,'\0',256);
	
	// getopt
	int index;
	int c;
	opterr = 0;

	if(argc == 2 && !strcmp(argv[1],"--help")) { // napoveda --help
		printf("Resolver xplsek03\n\npouziti: [-x] [-6] [-r] -s server [-p] ip|domena\n-x\treverzni dotaz\n-6\tAAAA dotaz\n-r\trekurzivni dotaz\n-s\tdns server\n-p\tport\n");
		return 0;
	}

	if(argc >= 4 && argc <= 9) { // argumentu je spravny pocet

		// INSPIRACE START
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
					if (optopt == 'p' || optopt == 's') { // chybejici hodnoty
						fprintf (stderr, "U argumentu -%c chybi hodnota.\n", optopt);
					}
					else if (isprint (optopt)) { // neni printable
						fprintf (stderr, "Neznamy argument: `-%c'.\n", optopt);
					}
					else { // neznama moznost
						fprintf (stderr,"Neznamy argument `\\x%x'.\n",optopt);
					}
					return 1;

				default:
					abort(); // ukonci parsovani
			}
		}
		// INSPIRACE END
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

	if(x_on) { // zapnuty reverzni dotaz
	
		if(!revert_ip(ip_val, six_on)) { // zvaliduj jestli je to IP adresa a zaroven ji revertuj kvuli rDNS
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
    
    if(six_on) { // je pozadovan dotaz IPv6
    	v6 = true; // je potreba odeslat AAAA dotaz pres IPv6, jestli je to mozne se ukaze pri odesilani
    }
    
	if(!validate_ip(s_val, &v6, six_on)) { // zadany server neni platna ip adresa
	
		validate_hostname(s_val, six_on); // vrat funkcni ip adresu z domenoveho jmena a nahrad za puvodni hostname

		if(!strlen(s_val)) { // nenaslo to zadnou adresu, ktera by se dala pouzit
			fprintf (stderr,"Nepodarilo se pripojit k zadne IP adrese zadaneho dns serveru.\n");
			return 1;
		}
		
		// validate_ip(s_val, &v6, six_on); // po nalezeni ip adresy nastav jestli se jedna o ipv4 nebo ipv6. NENI POTREBA
	}

	// ******** PLNENI DATAGRAMU *********

	int size = 0; // zarazka, aby nebylo potreba prepocitavat pozici v datagramu
	unsigned char dgram[65536]; // datagram
	HEADER *header = (HEADER *)&dgram; // hlavicka dns
	header->id = (unsigned short)htons(getpid());
	header->guts = htons(0); // abychom nemuseli pouzivat bitove pole, nastavime jednotlive bity
	if(r_on) { // bit rekurze
		header->guts ^= 1UL << 0; // nulty bit, LittEnd? POZN: xxxxxxx1  <-(1) xxxxxxxx <-(2)
	}

	header->qcount = htons(1); // mame 1 pozadavek 
	header->acount = htons(0);
	header->aucount = htons(0);
	header->addcount = htons(0);
	
	size = sizeof(HEADER); // preskoc hlavicku dns
	
	unsigned char *position = (unsigned char *)&dgram[size]; // aktualni pozice v dgramu, pouziva se ve fcich
	
	dns_format(position, ip_val); // preved adresu do dns formatu
	
	size += strlen((const char *)position) + 1; // skoc za question name

	Q *q = (Q *)&dgram[size]; // question type + class
	if(x_on) { // -x
		q->type = htons(12); // PTR, reverzni lookup
	}
	else if(six_on) { // -6
		q->type = htons(28); // AAAA
	}
	else { // defualtni A dotaz
		q->type = htons(1); // A
	}
	
	q->cl = htons(1); // IN

	size += sizeof(Q); // skoc za question

	// ******** ODESLANI DATAGRAMU *********

	int s; // socket

	if(v6) { // pouzij IPv6
    	struct sockaddr_in6 dest; // server socket
    	memset(&dest, 0, sizeof(dest));
    	dest.sin6_family = AF_INET6;
    	dest.sin6_port = htons(p_val); // port
		inet_pton(AF_INET6, s_val, &(dest.sin6_addr)); // ipv6 addr
		
		s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP); // otevri socket
		if(s == -1) {
			fprintf(stderr,"Nelze vytvorit socket.\n");
			return 1;
		}
		struct timeval timeout; // timeout socketu
		timeout.tv_sec = 5; // nastav timeout na 5s, kdyby neprisla odpoved 
		if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
			perror("Setsockopt error.\n");
			return 1;
		}
		
		if(sendto(s, dgram, size, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) { // odeslani datagramu
			perror("Chyba pri odesilani dat.\n");
			return 1;
		}
		int incoming = sizeof(dest);
		if(recvfrom(s,dgram, 65536 , 0, (struct sockaddr*)&dest, (socklen_t*)&incoming) < 0) { // cekani na data
			perror("Chyba pri prijimani dat.\n");
			return 1;
		}
	}
	else { // IPv4
    	struct sockaddr_in dest; // server socket
    	memset(&dest, 0, sizeof(dest));
    	dest.sin_family = AF_INET;
    	dest.sin_addr.s_addr = inet_addr(s_val); // ipv4 adresa
    	dest.sin_port = htons(p_val); // port
    	
		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // otevri socket
		if(s == -1) {
			fprintf(stderr,"Nelze vytvorit socket.\n");
			return 1;
		}
		struct timeval timeout; // timeout socketu
		timeout.tv_sec = 5; // nastav timeout na 5s, kdyby neprisla odpoved 
		if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
			perror("Setsockopt error.\n");
			return 1;
		}
		
		if(sendto(s, dgram, size, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) { // odeslani datagramu
			perror("Chyba pri odesilani dat.\n");
			return 1;
		}
		int incoming = sizeof(dest);
		if(recvfrom(s,dgram, 65536 , 0, (struct sockaddr*)&dest, (socklen_t*)&incoming) < 0) { // cekani na data
			perror("Chyba pri prijimani dat.\n");
			return 1;
		}
	}
    
	
    // ******** ZPRACOVANI ODPOVEDI *********

	header = (HEADER *)&dgram; // dns hlavicka

	if(header->id == htons(getpid()) && ((htons(header->guts) >> 15) & 1U)) { // id dotazu odpovida id odpovedi a je to odpoved

		if(r_on && !((htons(header->guts) >> 15) & 1U)) { // pokud chceme rekurzi a neni dostupna, vyhod chybu
			fprintf(stderr,"Rekurze neni na tomto serveru dostupna.\n");
			return 1;
		}
		
		if(((htons(header->guts) >> 0) & 1U) || ((htons(header->guts) >> 1) & 1U) 
		|| ((htons(header->guts) >> 2) & 1U) || ((htons(header->guts) >> 3) & 1U)) { // pokud se vyskytla nektera z chyb opcode
		
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
			else { // jiny chybovy kod nez 1-5
				fprintf(stderr,"Neznama chyba.\n");
				return 1;
			}
		}

		printf("AUTORITATIVNI\t%s\n", ((htons(header->guts) >> 10) & 1U) ? "ano" : "ne"); // AA bit set
		printf("ZKRACENO\t%s\n", ((htons(header->guts) >> 9) & 1U) ? "ano" : "ne"); // TC bit set
		printf("REKURZE \t%s\n", (((htons(header->guts) >> 7) & 1U) && ((htons(header->guts) >> 8) & 1U)) ? "ano" : "ne");
		// rekurzivni pouze v pripade, ze byla pozadovana rekurze a zaroven je nastavena rekurze dostupna na serveru
	
		printf("\n");
		
		if(ntohs(header->qcount) == 1) { // ptali jsme se na jedinou otazku
			
			size = sizeof(HEADER); // parsovani zacina za hlavickou
			position = (unsigned char *)&dgram[size]; // ukazatel na zacatek question retezce
		
			unsigned char content[256]; // buffer pro vysledek parsovani
			memset(content,'\0',256);
			
			int pos = 0; // zarazka, kde skoncilo parsovani, uklada se do nej delka retezcu
							
			parser(content, position, dgram, &pos); // naparsuj question name
			
			size += pos; // dostan se za question name
			
			q = (Q *)&dgram[size]; // naparsovani quesiton class a question type
			
			// promenne k parsovani odpovedi
			char tp[6];
			memset(tp,'\0',6);
			char cl[3];
			memset(cl,'\0',3);
			
			// trida
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
			
			// typ
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
		
		
			
		else { // pokud neobsahuje question nebo jich obsahuje vic
			fprintf(stderr,"Datagram neobsahuje dotaz nebo je vic nez 1.\n");
			return 1;
		}     	
    }
     
	return 0;	
}
