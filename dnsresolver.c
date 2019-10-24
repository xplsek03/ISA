#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#include "functions.h"

int main (int argc, char **argv) {

	// flagy
	bool r_on = false; // recurse
	bool x_on = false; // reverse
	bool six_on = false; // ipv6
	bool s_on = false; // server musi byt zadany
    bool p_on = false; // port

	// hodnoty
	int p_val; // cilova hodnota portu jako int
	char s_val[255]; // server
	char *p_val_str = "53"; // port jako string
	char *ip_val = NULL; // dotazovana adresa

	// countery getopt
	int index;
	int c;

	char *replace; // retezec pro pripad prevodu serveru na ip
	bool free_replace = false; // abychom nevolali free na neco co jsme nealokovali
	
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
                    p_on = true;
					p_val_str = optarg;
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
		ip_val = argv[index]; // uloz query ip adresu
	}

	if(!b) { // chybi ip adresa query
		fprintf (stderr,"Chybi query ip adresa.\n");
		return 1;
	}

	if(x_on) {// zapnuty reverzni dotaz
		if(!validate_ip(ip_val)) { // pri reverznim dotazu muze byt dotazovana pouze ip adresa
            fprintf(stderr, "Dotazovana adresa neni adresou.\n");
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

	if(!validate_ip(s_val)) { // zadany server neni platna ip adresa

		free_replace = true; // v pripade ze budeme muset v budoucnu zavolat free() na s_val
		replace = validate_hostname(s_val); // vrat funkcni ip adresu z domenoveho jmena
		strcpy(s_val, replace); // nahrad puvodni hostname serveru jeho ip adresou

		if(!strlen(replace)) {
			fprintf (stderr,"Nepodarilo se pripojit k zadne IP adrese zadaneho dns serveru.\n");
			goto error;
		}
	}
	
	// ******** REVERZNI DOTAZ *************
	
	if(x_on) {
		reverse_dns(ip_val);
	}
	
	// ******** OBYCEJNY DOTAZ *************
	
	else {

		// ******** PLNENI DATAGRAMU *********
	
		unsigned char dgram[65536]; // datagram
	
		// struktury datagramu
		HEADER *header = NULL; // hlavicka
		Q *q = NULL; // query
		int size = 0; // aby nebylo potreba prepocitavat pozici v datagramu
	
		header = (HEADER *)&dgram;
		header->id = (unsigned short)htons(getpid());
		header->qr = 0;
		header->opcode = 0;
		header->aa = 0;
		header->tc = 0;
		if(r_on)
			header->rd = 1; // pokud je zapnuta rekurze
		else
			header->rd = 0;
		header->ra = 0;
		header->z = 0;
		header->ad = 0;
		header->cd = 0;
		header->rcode = 0;
		header->qcount = htons(1); // jediny pozadavek 
		header->acount = 0;
		header->aucount = 0;
		header->addcount = 0;
		
		size = sizeof(HEADER);
		
		char *q_name = (unsigned char *)&dgram[size];
		
		dns_format(q_name, ip_val); // preved adresu do dns formatu
		
		size += strlen((const char *)q_name) + 1;
	
		q = (Q *)&dgram[size];
		if(six_on)
			q->type = htons(2); // AAAA
		else
			q->type = htons(1); // A
		q->cl = htons(1); // IN
	
		size += sizeof(Q);

		// ******** ODESLANI DATAGRAMU *********
	
    	struct sockaddr_in dest; // serversocket
    	dest.sin_family = AF_INET;
    	dest.sin_addr.s_addr = inet_addr(s_val); // adresa
    	dest.sin_port = htons(p_val); // port
 	
    	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // socket pro odeslani
	
		if(sendto(s, dgram, size, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) { // odeslani datagramu
        	perror("Chyba pri odesilani dat.\n"); // vystup s kodem na stderr
        	goto error;
    	}
    	
    	// ******** ZPRACOVANI ODPOVEDI *********
    
    	
    
    }
    
	// ******* KONEC *******
	
	return 0;	
	
	error: // od radku 
		if(free_replace) // pokud jsme alokovali char *replace, uvolni ho
			free(replace);
		return 1;
	
}
