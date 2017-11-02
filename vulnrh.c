#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define CHK_ERR(err,s) if ((err)==1) { puts("ERROR "); perror(s); exit(1); }
#define CHK_NULL(x) if ((x) == NULL) exit(1);


typedef struct packet {
	unsigned char code [1];
	unsigned char len  [2];
	unsigned char msg  [128];
} Packet;

/* GLOBALS */
Packet p;

/* Debug */
void
hnput(unsigned char *dst, uint32_t src, size_t n){
	unsigned int i;
	
	/* MSB in dst[0] */
	for(i=0; n--; i++)
		dst[i] = (src >> (n*8)) & 0xff;
}
uint16_t
nhgets(unsigned char c[2]){
	return ((c[0]<<8) + c[1]) & 0xffff;
}
uint32_t
nhgetl(unsigned char c[4]){
	return (nhgets(c)<<16)+nhgets(c+2);
}
void
segdump(Packet *p) {
	char buf[130];
	memcpy(buf, p, sizeof(buf));
	uint8_t c = (uint8_t) *p->code;
	uint16_t l = nhgets(p->len);
	/* cast to (void *) to avoid warnings */
	printf("%p\n[c: 0x%hx][l: 0x%hx][m: %s]\n", 
		(void *)p, c, l, p->msg);
}


char *
makekey(void);

int
getkey(char *key);

char *
enc(char *key, char *mbuff);

char *
dec(char *key, char *cbuff);

void
senddat(char *buffer, size_t blen);

enum {
	Error	= 1,
	Message = 2,
	Crypt	= 4,
	Decrypt = 5,
};

void
run(int sock) {
	unsigned char buf[128];
	int err = write(sock, "hello", strlen("hello"));
	CHK_ERR(err, "Hello packet");

	/* read the data */
	memset(&p, 0, sizeof(p));
	puts("---");
	read(sock, buf, 128);
	memcpy(&p, buf, nhgets(buf[1]));

	switch(buf[1]) {
	case Error:
		printf("message with ERROR");
		return;
	case Message:
	       printf("msg: %s\n", p.msg);
	case Crypt:
	       encmsg(p.msg);
	case Decrypt:
	       decmsg(p.msg);
	Default:
	       return;
}

int
main(int argc, char* argv[]) {
	int lsock, nsock; /* listen socket and new socket for client */
	struct sockaddr_in saddr;
	int sport = 4545;
	
	signal(SIGTERM, LEAVE);

	lsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	CHK_ERR(lsock, "socket");

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(sport);

	int err = bind(lsock, (struct sockaddr*) &saddr, sizeof(saddr));
	CHK_ERR(err, "bind");

	err = listen(lsock, 5);
	CHK_ERR(err, "listen");
	
	struct sockaddr_in caddr; /* client addr structure */
	socklen_t caddrlen;

	while(1) {
		char caddr_s[INET_ADDRSTRLEN];
		int pid;
		
		nsock = accept(lsock, (struct sockaddr*) &caddr, &caddrlen);
		CHK_ERR(nsock, "ERROR on accepting new socket");
		
		inet_ntop(AF_INET, &(caddr.sin_addr), caddr_s, INET_ADDRSTRLEN);
		printf("Connection from %s, port %d\n", 
				caddr_s, ntohs(caddr.sin_port));

		pid = fork();
		CHK_ERR(pid, "ERROR on forking");
		if(pid == 0) {
			close(lsock);
			run(nsock);
			//interactive(nsock);
			puts("fork: exiting normally...");
			exit(0);
		} else {
			close(nsock);
		}
	}
LEAVE:
	puts("closing...\n");
	close(nsock);
	return 0;
}
