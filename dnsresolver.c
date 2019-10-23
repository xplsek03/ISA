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

	bool free_replace = false; // abychom nevolali free na neco co jsme nealokovali

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
		char *replace = validate_hostname(s_val); // vrat funkcni ip adresu z domenoveho jmena
		strcpy(s_val, replace); // nahrad puvodni hostname serveru jeho ip adresou
	
		if(!strlen(replace)) {
			fprintf (stderr,"Nepodarilo se pripojit k zadne IP adrese zadaneho dns serveru.\n");
			free(replace);
			return 1;		
		}
	}

	// ******** KONEC OVEROVANI *********

	char *url = "www.google.com";
	char neu[257]; // nula na konci
	dns_format(url, neu);
	printf("FORMED: %s\n",neu);

	// konec overeni, podle techto argumentu zacni skladat hlavicku a telo dotazu kterej posles ven
	printf("r: %d x: %d 6: %d server: %s port: %i ip: %s\n", r_on, x_on, six_on, s_val, p_val, ip_val);
	
	// PRI CHYBE ZKOUMEJ JESTLI JE free_replace == TRUE. Pokud jo tak: free(replace)

	return 0;

}

typedef struct dns {
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
	unsigned short qestion_count; // c: query structs
	unsigned short answer_count; // c: rr struct
	unsigned short auth_rr_count; // c: rr struct
	unsigned short add_rr_count; // c: rr struct
} dns_header;

typedef struct q {
	unsigned char *name; // domena: *q = malloc(sizeof(struct q)); name = malloc(sizeof(char)); p->name = malloc(strlen(name)+1); strcpy(p->name, name);
	unsigned short type; // zajima nas 1=A, 5=CNAME
	unsigned short cl; // zajima nas 1=IN(ternet)
} dns_question;

typedef struct rr {
	unsigned char *name; // rr name
	unsigned short type; // zajima nas 1=A, 5=CNAME
	unsigned short cl; // zajima nas 1=IN(ternet)
	unsigned int ttl; // time to live
	unsigned short rdlength; // delka rdata v bytech
	// + RDATA: 32b v4 nebo v6 16*oktet
} dns_rr;
