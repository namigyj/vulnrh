#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/aes.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define KEYLEN 16

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

typedef struct keymap {
	uint32_t ip;
	unsigned char key[KEYLEN];
} Keymap;

/* GLOBALS */
Keymap **km = NULL;
size_t nkm;

static const unsigned char masterkey[] = {
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 
	0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
};


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
/* Debug */
void
segdump(Segment *s) {
	char buf[130];
	memcpy(buf, s, sizeof(buf));
	uint8_t c = (uint8_t) *s->code;
	uint16_t l = nhgets(s->len);
	/* cast to (void *) to avoid warnings */
	printf("segdump : %p [c: 0x%hx][l: 0x%hx][m: %s]\n", 
		(void *)s, c, l, s->msg);
}


int
addkey(uint32_t ipaddr) {
	if (nkm == 0)
		km = malloc(sizeof(Keymap *));
	else
		km = realloc(km, (nkm+1)*sizeof(Keymap *));
	
	km[nkm] = (Keymap *) malloc(sizeof(*km)); 
//dbg	printf("km=%p\n",(void *)km, (void *)km+(sizeof (km[0])));
	
	km[nkm]->ip = ipaddr;
	hnput(km[nkm]->key, ipaddr, 4);
	memcpy(km[nkm]->key, masterkey, KEYLEN);

	nkm++;
	return 0;
}

int
loadkeys(void) {
	/* todo : loadkeys from file */
	/* todo : secure file
	 * note : it's not possible, the system is broken tbh
	 */
	return 0;
}

unsigned char *
getkey(uint32_t ipaddr) {
	unsigned int i;

	if ( km == NULL) {
		if(loadkeys() == 0) return 0;
	}
	for(i=0; i<nkm; i++)
		if(km[i]->ip == ipaddr) return km[i]->key;

	return 0;
}

Segment *
encmsg(unsigned char *ptxt, size_t tsize){
	printf("debug: encrypting %s\n", ptxt);

	AES_KEY enkey;
	unsigned char ctxt[AES_BLOCK_SIZE];
	Segment *rseg;

        rseg = calloc(1, sizeof(*rseg));
	AES_set_encrypt_key(masterkey, 128, &enkey);

	AES_encrypt(ptxt, (unsigned char *) &ctxt, &enkey);
	/* setup segment */
	hnput(rseg->len, AES_BLOCK_SIZE, 2);
	memcpy(rseg->msg, &ctxt, AES_BLOCK_SIZE);
	hnput(rseg->code, Cryptd, 1);
	return rseg;
}

Segment *
decmsg(unsigned char *ctxt, size_t tsize) {
	printf("debug: decrypting ");
	
	for(int i=0; i < tsize; i++) printf("%hhx", ctxt[i]);
	printf("\n");

	AES_KEY dekey;
	unsigned char ptxt[AES_BLOCK_SIZE];
	Segment *rseg;
        
	rseg = calloc(1, sizeof(*rseg));
	AES_set_decrypt_key(masterkey, 128, &dekey);

	AES_decrypt(ctxt, (unsigned char *) &ptxt, &dekey);

	hnput(rseg->len, AES_BLOCK_SIZE, 2);
	memcpy(rseg->msg, &ptxt, AES_BLOCK_SIZE);
	hnput(rseg->code, Decryptd, 1);
	return rseg;
}

void
segsend(int sock, Segment *s, size_t ss) {
	write(sock, s, ss);
}

void
freekm(void) {
	for(;nkm--;) free(km[nkm]);
}
void
sighandler(int ihavenofuckingideawhattodowiththis) {
	printf("signal called");
	freekm();
	_exit(0);
}

Segment seg;
void
test(void) {
/*
	addkey(0x42424242);
	addkey(0x43434343);
	printf("[0]:%d,%s\n[1]:%d,%s\n", 
		km[0]->ip, km[0]->key, km[1]->ip, km[1]->key);
	freekm();
*/
	memset(&seg, 0, sizeof(seg));
	hnput(seg.code, Crypt, 1);
	hnput(seg.len, AES_BLOCK_SIZE, 2);
	strcpy(seg.msg, "this is a test\0\0");
}

void
run(int sock) {
	int err;
	unsigned char buf[128];
	size_t dlen, segsize;
	
	err = write(sock, "hello", strlen("hello"));
	CHK_ERR(err, "ERROR: Hello packet");
	
//	Segment seg;
	Segment *rseg;
	int n = 2;
	while(n--) {
	/* read the data */
	memset(&seg, 0, sizeof(seg));
	puts("---");
	read(sock, buf, 128);
	dlen = nhgets(buf+1);
	memcpy(&seg, buf, dlen+3);
	printf("received : ");
	segdump(&seg);

	switch(buf[0]) {
	case Error:
		printf("message with ERROR\n");
		return;
	case Message:
		printf("msg: %s\n", seg.msg);
		return;
	case Crypt:
		rseg = encmsg(seg.msg, dlen);
		segdump(rseg);
		err = write(sock, rseg, nhgets(rseg->len)+3);
		CHK_ERR(err, "enc: error while writing to sock");
		free(rseg);
		break;
	case Decrypt:
		rseg = decmsg(seg.msg, dlen);
		segdump(rseg);
		write(sock, rseg, nhgets(rseg->len)+3);
		free(rseg);
		break;
	default:
		printf("defaults: %hhx\n", buf[0]);
		return;
	}
	}
}

int
main(int argc, char* argv[]) {
	int lsock, nsock; /* listen socket and new socket for client */
	struct sockaddr_in saddr;
	int sport = 4545;

//	run(123);

	signal(SIGINT, sighandler);
	signal(SIGTERM, sighandler);

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
			puts("fork: exiting normally...");
			exit(0);
		} else {
			close(nsock);
		}
	}
	puts("closing...\n");
	freekm();
	close(nsock);
	return 0;
}
