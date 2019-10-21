#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

int main (int argc, char **argv) {
	
	// flagy
	bool r_on = false; // recurse
	bool x_on = false; // reverse
	bool six_on = false; // ipv6
	bool s_on = false; // server musi byt zadany
 
	// hodnoty
	char *s_val = NULL; // server
	char *p_val = "53"; // port
	char *ip_val = NULL; // dotazovana adresa
	  
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
					s_val = optarg;
					break;
				case 'p':
					p_val = optarg;
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
		
	// overeni serveru, muze byt host / ip
	; // over na host a pak na ip jestli je alespon jedno
	// pokud je host rpeved na ip: https://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
	
	
	if(x_on) // zapnuty reverzni dotaz
		; // musi byt pouze ip
	else
		; // musi byt pouze host
		
	// overeni cisla portu jestli je int od 0-65535 vcetne
		;

	// konec overeni, podle techto argumentu zacni skladat hlavicku a telo dotazu kterej posles ven
	printf("r: %d x: %d 6: %d server: %s port: %s ip: %s\n", r_on, x_on, six_on, s_val, p_val, ip_val);

	
	return 0;
	
}


// VALID IP ADDR
//     struct sockaddr_in sa;
//    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
//    return result != 0;

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
