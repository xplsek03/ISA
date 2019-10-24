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


// over jestli se jedna o validni ip adresu
bool validate_ip(char *ip) {
	struct sockaddr_in sa;
	int result; // vyzkousej obe moznosti, IPv4 i IPv6
	if(inet_pton(AF_INET, ip, &(sa.sin_addr)) || inet_pton(AF_INET6, ip, &(sa.sin_addr)))
		return true;
	return false;
}

// over zda se jedna o validni port
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
char *validate_hostname(char *hostname) {

	int sfd; // socket return
    struct addrinfo hints, *infoptr, *rp;
    memset(&hints, 0, sizeof(hints)); // vynulovani hints

    hints.ai_family = AF_UNSPEC; // nespecifikovano jestli ipv4 nebo ipv6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    int result = getaddrinfo(hostname, NULL, &hints, &infoptr);
    if (result) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(1); // protoze jsme v main nic nealokovali, muzeme pouzit bez obav exit()
    }

	char ip[256];

	char *new_ip = malloc(sizeof(char) * 256); // alokuj cilovou ip adresu
    memset(new_ip, '\0', 256);

    for (rp = infoptr; rp != NULL; rp = rp->ai_next) {

        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); // socket pro overeni funkcnosti adresy

        if (sfd == -1)
            continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) { // podarilo se navazat spojeni s jednou z adres
            getnameinfo(rp->ai_addr, rp->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST); // uloz adresu do bufferu
            break;
        }
        close(sfd);
    }

    if (rp == NULL) { // nebyly nalezeny zadne adresy k domenovemu jmenu
        fprintf(stderr, "Nelze navazat spojeni s hostname.\n");
        free(new_ip);
        exit(1);
    }

	freeaddrinfo(infoptr); // uvolni systemove alokovany buffer
    strcpy(new_ip,ip);
    return new_ip; // vrat nalezenou adresu nebo retezec delky 0
}

// over jestli je poptavana adresa validni retezec
void validate_string(char *url) {

	if(strlen(url) < 3 || strlen(url) > 255)
		goto fail;

	if(url[0] == '.' || url[0] == '-' || url[strlen(url)-1] == '.' || url[strlen(url)-1] == '-')
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

// funkce vypujcena od: https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168
void dns_format(unsigned char* dns, unsigned char* host) {
    int lock = 0, i;
    strcat((char*)host,".");
     
    for(i=0; i < strlen((char*)host); i++) {
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

// 
// funkce inspirovana z: http://man7.org/linux/man-pages/man3/getaddrinfo.3.html?fbclid=IwAR1nM16wJIbbV9qvZ6yES__aYIfzpN63QYpDA53Ce6t425TGtsAxvzpeu60
void reverse_dns(char *hostname) {

	int sfd; // socket return
    struct addrinfo hints, *infoptr, *rp;
    memset(&hints, 0, sizeof(hints)); // vynulovani hints

    hints.ai_family = AF_UNSPEC; // nespecifikovano jestli ipv4 nebo ipv6
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    int result = getaddrinfo(hostname, NULL, &hints, &infoptr);
    if (result) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(1); // protoze jsme v main nic nealokovali, muzeme pouzit bez obav exit()
    }

	char ip[256];

    for (rp = infoptr; rp != NULL; rp = rp->ai_next) {

        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol); // socket pro overeni funkcnosti adresy

        if (sfd == -1)
            continue;
        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) { // podarilo se navazat spojeni s jednou z adres
            getnameinfo(rp->ai_addr, rp->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST); // uloz adresu do bufferu
			printf("IP: %s\n",ip); // vytiskni adresu na vystup
        }
        close(sfd);
    }

    if (infoptr == NULL) { // nebyly nalezeny zadne adresy k domenovemu jmenu
        fprintf(stderr, "Nelze navazat spojeni s hostname.\n");
        exit(1);
    }

	freeaddrinfo(infoptr); // uvolni systemove alokovany buffer
}
