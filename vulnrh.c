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
#include <signal.h>

#define CHK_ERR(err,s) if ((err)==1) { puts("ERROR "); perror(s); exit(1); }
#define CHK_NULL(x) if ((x) == NULL) exit(1);


typedef struct segment {
	unsigned char code [1];
	unsigned char len  [2];
	unsigned char msg  [128];
} Segment;

enum {
	Error	= 1,
	Message = 2,
	Messagd = 3,
	Crypt	= 4,
	Cryptd  = 5,
	Decrypt = 6,
	Decryptd= 7,
};

/* GLOBALS */

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
segdump(Segment *s) {
	char buf[130];
	memcpy(buf, s, sizeof(buf));
	uint8_t c = (uint8_t) *s->code;
	uint16_t l = nhgets(s->len);
	/* cast to (void *) to avoid warnings */
	printf("%p\n[c: 0x%hx][l: 0x%hx][m: %s]\n", 
		(void *)s, c, l, s->msg);
}


char *
makekey(void);

int
getkey(char *key);

Segment *
encmsg(char *ptxt, size_t size){
	char ctxt[size+4];
	Segment *rseg;
	printf("sizeof(Segment) = %d", sizeof(Segment));
	memset(rseg, 0, sizeof(Segment));
	
	memcpy(ctxt, ptxt, size);
	strcpy(&ctxt[size], "enc");
	printf("new text : %s\n", ctxt);
	rseg->code[0] = (unsigned char) Cryptd;
	/* replace size */
	hnput(rseg->len, size+3, 2);
	memcpy(rseg->msg, ctxt, size+4);
	hnput(rseg->code, Cryptd, 1);
	return rseg;
}

char *
decmsg(char *cbuff) {
	return cbuff;
}

void
segsend(int sock, Segment *s, size_t ss) {
	write(sock, s, ss);
}

void
run(int sock) {
	unsigned char buf[128];
	size_t dlen, segsize;
	int err = write(sock, "hello", strlen("hello"));
	CHK_ERR(err, "ERROR: Hello packet");
	
	Segment seg;
	Segment *rseg;

	/* read the data */
	memset(&seg, 0, sizeof(seg));
	puts("---");
	read(sock, buf, 128);
	dlen = nhgets(buf+1);
	segsize = dlen+4;
	memcpy(&seg, buf, segsize);
	segdump(&seg);

	switch(buf[0]) {
	case Error:
		printf("message with ERROR\n");
		return;
	case Message:
		printf("msg: %s\n", seg.msg);
		return;
	case Crypt:
		printf("encrypting\n");
		rseg = encmsg(seg.msg, dlen);
		err = write(sock, rseg, sizeof(seg));
		CHK_ERR(err, "enc: error while writing to sock");
		break;
	case Decrypt:
		printf("decrypting\n");
		decmsg(seg.msg);
		write(sock, &seg, sizeof(seg));
		break;
	Default:
		printf("defaults: %hhx\n", buf[0]);
		return;
	}

}
int
main(int argc, char* argv[]) {
	int lsock, nsock; /* listen socket and new socket for client */
	struct sockaddr_in saddr;
	int sport = 4545;
	
	signal(SIGTERM, exit);

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
	puts("closing...\n");
	close(nsock);
	return 0;
}
