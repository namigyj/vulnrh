#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/aes.h>

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#define KEYLEN 16

#define CHK_ERR(err,s) if ((err)==1) { puts("ERROR "); perror(s); exit(EXIT_FAILURE); }
#define CHK_NULL(x) if ((x) == NULL) exit(EXIT_FAILURE);

void SIGhandler(int);

typedef struct segment {
    unsigned char code [1];
    unsigned char len  [2];
    unsigned char msg  [128];
} Segment;

enum {
    Error = 1,
    Message = 2,
    Messagd = 3,
    Crypt = 4,
    Cryptd  = 5,
    Decrypt = 6,
    Decryptd= 7,
};

/* ip key pair */
struct ipkey {
    uint32_t ip;
    unsigned char key[KEYLEN];
};
typedef struct iknode {
    struct ipkey ikpair;
    struct iknode *next;
} Iknode;

typedef struct _thread_data_t {
    int tid;
    int nsock;
    in_addr_t s_addr;
} thread_data_t;

/* GLOBALS */
/* head & tail of the IP-Key pair linked list */
Iknode *ikhd;
Iknode *iktl;
pthread_mutex_t lock_iklist;
int nsock;
FILE *file;

static const unsigned char testkey[] = {
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
    0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F
};


void hnput(unsigned char *dst, uint32_t src, size_t n){
    size_t i;

/* MSB in dst[0] */
    for(i=0; n--; i++)
        dst[i] = (src >> (n*8)) & 0xff;
}
uint16_t nhgets(unsigned char c[2]){
    return ((c[0]<<8) + c[1]) & 0xffff;
}
uint32_t nhgetl(unsigned char c[4]){
    return (nhgets(c)<<16)+nhgets(c+2);
}

/* Debug */
void printhex(unsigned char *txt, size_t len) {
    for(size_t i=0; i<len; i++)
        printf("%hhx", txt[i]);
}
void segdump(Segment *s) {
    char buf[130];
    memcpy(buf, s, sizeof(buf));
    uint8_t c = (uint8_t) *s->code;
    uint16_t l = nhgets(s->len);
    /* cast to (void *) to avoid warnings */
    printf("segdump : %p [c: 0x%hhx][l: 0x%hx][m: ",
        (void *)s, c, l);
    if ( c == Cryptd || c == Decrypt ) {
        printhex(s->msg, l);
    } else {
        for(int i=0; i<l; i++) printf("%c", s->msg[i]);
    }
    printf("]\n");
}

/* todo : fix this. It creates a new key at each fork()
 *                  Do forks not share memory with eachother ?
 */
/* Adds a ip/key pair to the ik list and return the key. */
unsigned char *addkey(uint32_t ipaddr) {
    Iknode **next;
    next = iktl ? &(iktl->next) : &ikhd;
    Iknode *new = malloc(sizeof(Iknode));

    /* [DJM] I think this is the only thing we should be worried about
     * since we're working with a linked list : having these 2 interleaved.
     */
    pthread_mutex_lock(&lock_iklist);
        *next = new;
        iktl = new;
    pthread_mutex_unlock(&lock_iklist);

    new->ikpair.ip = ipaddr;
    unsigned char nkey[KEYLEN];
    FILE* fr = fopen("/dev/urandom", "r");
    if (!fr) perror("cannot read urandom"), exit(EXIT_FAILURE);
    fread(nkey, sizeof(char), KEYLEN, fr);
    fclose(fr), fr = NULL;

    /* testing */
    // memcpy(km[nkm]->key, nkey, KEYLEN);
    memcpy(new->ikpair.key, testkey, KEYLEN);
    /*
    printf("[debug][addkey]: key added:");
    printhex(km[nkm-1]->key, KEYLEN);
    printf(" at %p\n", (void*)km[nkm-1]);
    */
    return new->ikpair.key;
}

/* todo : loadkeys from file [see README]
 */
uint32_t loadkeys(void) {
    return 0;
}

/* Return the key matching the ipaddr in Keymap.
 * Return 0 if no key is found.
 */
unsigned char *getkey(uint32_t ipaddr) {
    if ( ikhd == NULL) {
        if(loadkeys() == 0) return 0;
    }
    Iknode *cursor = ikhd;
    while(cursor) {
        if(cursor->ikpair.ip == ipaddr)
            return cursor->ikpair.key;
        cursor = cursor->next;
    }

    return 0;
}

/* todo : make it cleaner by adding a code inside the data
 *        but not as ascii to avoid parsing
 */
/* Make an error segment with an error message. */
Segment *mkerr(const void *errmsg) {
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
 *        use CBC
 *        Refactor
 */
/* Encrypts message and returns a segment with it. */
Segment *encmsg(unsigned char *ptxt, size_t psize, uint32_t ipaddr){
    AES_KEY enkey;
    int rounds;
    size_t msize;
    //unsigned char * ctxt;
    unsigned char *lkey, *ctxt;
    Segment *rseg;

    rounds = psize / 16;
    if(psize % 16 > 0) rounds++;
    ctxt = calloc(rounds, AES_BLOCK_SIZE);
    msize = rounds * AES_BLOCK_SIZE;

    printf("[debug]enc : rounds: %d, msize: %lu, psize %lu\n",
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
    free(ctxt);
    hnput(rseg->code, Cryptd, 1);
    return rseg;
}

/* todo : check errors
 *        Read a textbook to know how to decrypt in CBC mode on a HSM
 *          I mean, what if the data isn't sent in the right order ?
 *        Refactor
 */
/* Makes a segment with the message unencrypted passed. */
Segment *decmsg(unsigned char *ctxt, size_t psize, uint32_t ipaddr) {
    AES_KEY dekey;
    int rounds;
    size_t msize;
    //unsigned char *ptxt;
    unsigned char *lkey, *ptxt;
    Segment *rseg;

    rounds = psize /16;
    if(psize % 16 > 0) rounds++;
    ptxt= calloc(rounds, AES_BLOCK_SIZE);
    msize = rounds * AES_BLOCK_SIZE;

    printf("[debug]dec : rounds: %d, msize: %lu, psize %lu\n",
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
    free(ptxt);
    hnput(rseg->code, Decryptd, 1);
    return rseg;
}

ssize_t segsend(int fd, void *buf, size_t count) {
    Segment *sseg = buf;
    printf("[debug]sent : "); segdump(sseg);
    return write(fd, sseg, nhgets(sseg->len)+3);
}

void disposekeys(void) {
    puts("[debug][freekm]: freeing keymap");
    Iknode *cursor = ikhd;
    while(ikhd){
        Iknode *tmp = cursor->next;
        free(cursor);
        cursor = tmp;
    }

}

/* todo : read more on this. finally got it working but feels like cheaphack */
void SIGhandler(int ihavenofuckingideawhattodowiththis) {
    close(nsock);
    disposekeys();
    _exit(0);
}

/* todo : don't forget to delete this */
void test(void) {
    exit(0);
}

// todo : Refactor
void *run(void *arg) {
    int err;
    unsigned char buf[128];
    size_t dlen;
    thread_data_t *data = (thread_data_t *)arg;
    int sock = data->nsock;
    uint32_t ipaddr = data->s_addr;

    err = write(sock, "hello", strlen("hello"));
    CHK_ERR(err, "ERROR: Hello packet");

    /* keeping it a global until test func is no more needed */
    Segment seg;
    Segment *rseg;

    int n = 2;
    while(n--) {

        /* read the data */
        memset(&seg, 0, sizeof(seg));
        read(sock, buf, 128);
        dlen = nhgets(buf+1);
        memcpy(&seg, buf, dlen+3);
        printf("\n[debug]recv : "); segdump(&seg);

        switch((uint32_t)seg.code[0]) {
        case Error:
            /* in case the server has to handle errors on client */
            printf("message with ERROR\n");

            pthread_exit(NULL);
        case Message:
            /* in case control messages need to be sent/received */

            pthread_exit(NULL);
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

            pthread_exit(NULL);
        }

        //free(rseg);
    }
    puts("[debug]pthread : exiting normally...");
    pthread_exit(NULL);
}

/* TODO : Refactor the shit out of this function */
/* TODO : Replace fork() by pthread */
int main(int argc, char* argv[]) {
    int lsock, nsock; /* listen socket and new socket for client */
    struct sockaddr_in saddr;
    int sport = 4545;

    signal(SIGINT, SIGhandler);

    lsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(lsock, "ERROR on creating socket");

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(sport);

    int err = bind(lsock, (struct sockaddr*) &saddr, sizeof(saddr));
    CHK_ERR(err, "ERROR cannot bind socket");

    err = listen(lsock, 5);
    CHK_ERR(err, "starting listening socket");

    struct sockaddr_in caddr; /* client addr structure */
    socklen_t caddrlen;
    pthread_mutex_init(&lock_iklist, NULL);

    while(1) {
        char caddr_s[INET_ADDRSTRLEN];
        int pcnt = 0;

        nsock = accept(lsock, (struct sockaddr*) &caddr, &caddrlen);
        CHK_ERR(nsock, "ERROR on accepting new socket");

        inet_ntop(AF_INET, &(caddr.sin_addr), caddr_s, INET_ADDRSTRLEN);
        printf("\n---\nConnection from %s : %d\n",
                caddr_s, ntohs(caddr.sin_port));

        pthread_t thr;
        thread_data_t thr_data;
        thr_data.s_addr = caddr.sin_addr.s_addr;
        thr_data.nsock = nsock;
        thr_data.tid = pcnt++;
        int errno;
        if((errno = pthread_create(&thr, NULL, run, &thr_data))) {
            fprintf(stderr, "error: creating new thread, errno: %d\n", errno);
            close(nsock);
        }

    }
    puts("closing...\n");
    disposekeys();
    close(nsock);
    return EXIT_SUCCESS;
}
/* randu.org/tutorials/threads/ */
