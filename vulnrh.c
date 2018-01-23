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

void SIGhandler(int);

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
int nsock;
FILE *file;

static const unsigned char testkey[] = {
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
	printf("segdump : %p [c: 0x%hx][l: 0x%hx][m: ", 
		(void *)s, c, l);
	if ( c == Cryptd || c == Decrypt ) { 
		for(int i=0; i<l; i++) printf("%hhx", s->msg[i]);
	} else {
		for(int i=0; i<l; i++) printf("%c", s->msg[i]);
	}
	printf("]\n");
	
}


unsigned char *
addkey(uint32_t ipaddr) {
	if (nkm == 0)
		km = malloc(sizeof(Keymap *));
	else
		km = realloc(km, (nkm+1)*sizeof(Keymap *));
	
	km[nkm] = (Keymap *) malloc(sizeof(*km)); 
//dbg	printf("km=%p\n",(void *)km, (void *)km+(sizeof (km[0])));
	
	km[nkm]->ip = ipaddr;

	unsigned char nkey[KEYLEN];
	FILE* fr = fopen("/dev/urandom", "r");
	if (!fr) perror("cannot read urandom"), exit(EXIT_FAILURE);
	fread(nkey, sizeof(char), KEYLEN, fr);
	fclose(fr), fr = NULL;

	/* testing */
	// memcpy(km[nkm]->key, nkey, KEYLEN);
	memcpy(km[nkm]->key, testkey, KEYLEN);
	nkm++;
	return km[nkm-1]->key;
}

/* todo : loadkeys from file
 *        secure file (it's useless, the system is broken tbh)
 */
int
loadkeys(void) {
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

/* todo : make it cleaner by adding a code inside the data
 *        but not as ascii to avoid parsing
 */
Segment *
mkerr(const void *errmsg) {
	Segment *rseg;
	size_t errlen;

	errlen = strlen(errmsg) +1;
	rseg = calloc(1, sizeof(*rseg));
	hnput(rseg->code, Error, 1);
	hnput(rseg->len, errlen, 2);
	memcpy(rseg->msg, errmsg, errlen);

	return rseg;
}

/* todo : check errors
 *        use something better than AES_encrypt
 *        don't use ECB
 */
Segment *
encmsg(unsigned char *ptxt, size_t psize, uint32_t ipaddr){
	int rounds;
	size_t msize;
	//unsigned char * ctxt;
	unsigned char *lkey, *ctxt;
	Segment *rseg;
	AES_KEY enkey;
	
	rounds = psize / 16;
	if(psize % 16 > 0) rounds++;
	ctxt = calloc(rounds, AES_BLOCK_SIZE);
	msize = rounds * AES_BLOCK_SIZE;
	/* debug */
	printf("\n[debug]: rounds: %d, msize: %ld, psize %ld\n",
			rounds, msize, psize);
	if((lkey = getkey(ipaddr)) == 0){ 
	/* the error handling here is probably very useless */
		if((lkey = addkey(ipaddr)) == NULL)
			fprintf(stderr, "ERROR: addkey failed\n");
	}
	AES_set_encrypt_key(lkey, 128, &enkey);
	
	for(int i=0; rounds--;i+=16) {
		AES_encrypt(ptxt+i, ctxt+i, &enkey);
		/* debug */
		// for(int j=i; j-i < 16; j++) printf("%x", ptxt[j]);
	}
	
	/* make the segment */
	rseg = calloc(1, sizeof(*rseg));
	hnput(rseg->len, msize, 2);
	memcpy(rseg->msg, ctxt, msize);
	hnput(rseg->code, Cryptd, 1);
	return rseg;
}

/* todo : check errors
 *        Read a textbook to know how to decrypt in CBC mode on a HSM
 *          I mean, what if the data isn't sent in the right order ?
 */
Segment *
decmsg(unsigned char *ctxt, size_t psize, uint32_t ipaddr) {
	AES_KEY dekey;
	//unsigned char *ptxt;
	size_t msize;
	int rounds;
	unsigned char *lkey, *ptxt;
	Segment *rseg;

	rounds = psize /16;
	if(psize % 16 > 0) rounds++;
	ptxt= calloc(rounds, AES_BLOCK_SIZE);
	msize = rounds*AES_BLOCK_SIZE;

	printf("\n[debug]: rounds: %d, msize: %ld, psize %ld\n",
			rounds, msize, psize);

	if((lkey = getkey(ipaddr)) == 0){ 
	/* the error handling here is probably very useless */
		if((lkey = addkey(ipaddr)) == NULL)
			fprintf(stderr, "ERROR: addkey failed\n");
	}
	AES_set_decrypt_key(lkey, 128, &dekey);

	for(int i=0; rounds--; i+=16) {
		AES_decrypt(&ctxt[i], ptxt+i, &dekey);
		/* debug */
		// for(int j=i; j-i < 16; j++) printf("%hhx", ptxt+j);
	}

	/* make the segment */
	rseg = calloc(1, sizeof(*rseg));
	hnput(rseg->len, msize, 2);
	memcpy(rseg->msg, ptxt, msize);
	hnput(rseg->code, Decryptd, 1);
	segdump(rseg);
	return rseg;
}

ssize_t
segsend(int fd, void *buf, size_t count) {
	Segment *sseg = buf;
	printf("[debug]sent : "); segdump(sseg);
	return write(fd, sseg, nhgets(sseg->len)+3);
}


void
freekm(void) {
	while(nkm--) free(km[nkm]);
}

/* todo : read more on this. finally got it working but feels like cheaphack */
void
SIGhandler(int ihavenofuckingideawhattodowiththis) {
	close(nsock);
	freekm();
	_exit(0);
}

void
test(void) {
/*
	addkey(0x42424242);
	addkey(0x43434343);
	printf("[0]:%d,%s\n[1]:%d,%s\n", 
		km[0]->ip, km[0]->key, km[1]->ip, km[1]->key);
	freekm();
*//*
	memset(&seg, 0, sizeof(seg));
	hnput(seg.code, Crypt, 1);
	hnput(seg.len, AES_BLOCK_SIZE, 2);
	strcpy((char *)seg.msg, "this is a test\0\0");
*/
	segdump(mkerr("02: testing this error"));
	exit(0);

}

void
run(int sock, uint32_t ipaddr) {
	int err;
	unsigned char buf[128];
	size_t dlen;
	
	err = write(sock, "hello", strlen("hello"));
	CHK_ERR(err, "ERROR: Hello packet");

	/* keeping it a global until test func is no more needed */
	Segment seg;
	Segment *rseg;

	puts("---");
	int n = 2;
	while(n--) {

		/* read the data */
	memset(&seg, 0, sizeof(seg));
	read(sock, buf, 128);
	dlen = nhgets(buf+1);
	memcpy(&seg, buf, dlen+3);
	printf("[debug]recv : "); segdump(&seg);

	switch((int)seg.code[0]) {
	case Error:
		/* in case the server has to handle errors on client */
		printf("message with ERROR\n");
		return;
	case Message:
		/* in case control messages need to be sent/received */
		printf("msg: %s\n", seg.msg);
		return;
	case Crypt:
		rseg = encmsg(seg.msg, dlen, ipaddr);
		err = segsend(sock, rseg, nhgets(rseg->len)+3);
		CHK_ERR(err, "enc: error while writing to sock");
		break;
	case Decrypt:
		rseg = decmsg(seg.msg, dlen, ipaddr);
		err = segsend(sock, rseg, nhgets(rseg->len)+3);
		CHK_ERR(err, "dec: error while writing to sock");
		break;
	default:
		printf("[debug]unhandled code:%hhx\n", buf[0]);
		mkerr("01:request unknown");
		return;
	}
	free(rseg);
	}
}

int
main(int argc, char* argv[]) {
	int lsock, nsock; /* listen socket and new socket for client */
	struct sockaddr_in saddr;
	int sport = 4545;

	signal(SIGINT, SIGhandler);

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
		printf("Connection from %s(%d), port %d\n", 
				caddr_s, caddr.sin_addr.s_addr, ntohs(caddr.sin_port));
		
		/* what about writing/reading from file atsame time */
		pid = fork();
		CHK_ERR(pid, "ERROR on forking");
		if(pid == 0) {
			close(lsock);
			run(nsock, caddr.sin_addr.s_addr);
			puts("[debug]fork: exiting normally...");
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

