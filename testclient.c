#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define CHK_ERR(err,s) if (err==-1) { error(s) }
#define error(s) { perror(s); exit(1);}

enum {
	Error	= 1,
	Message = 2,
	Messagd = 3,
	Crypt	= 4,
	Cryptd  = 5,
	Decrypt = 6,
	Decryptd= 7,
};
/*utils{{{*/
uint16_t
nhgets(unsigned char c[2]){
	return ((c[0]<<8) + c[1]) & 0xffff;
}
/*}}}*/

/*test{{{*/
void
test() {
	char * string = "0123456789";
	char * str = string;
	size_t s = 10;
	int rn;
	rn = 10/2;
	if(10%2 > 0) rn++;
	while(rn--) {
		printf("%c%c\n",str[0],str[1]);
		str += 2;
	}
	exit(EXIT_SUCCESS);
}
/*}}}*/
int
main(int argc, char *argv[]) {
	//test();
/*Preambule{{{*/
	int sockfd, portno, err;
	struct sockaddr_in saddr;
	struct hostent *shost;
	char buffer[256];

	if ((argc == 2) && !(strcmp(argv[1], "test"))) {
		test();
	} else if (argc < 3 ) {
		fprintf(stderr, "usage %s hostname port [text]\n", argv[0]);
		exit(0);
	}

	portno = atoi(argv[2]);
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(sockfd, "ERROR socket: opening socket");
	shost = gethostbyname(argv[1]);
	if (shost == NULL)
		error("ERROR hostname: no such host");

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	/*bcopy((char *)shost->h_addr,
	      (char *)&saddr.sin_addr.s_addr,
	      shost->h_length);
	*/
	memcpy((char *)shost->h_addr_list[0], 
		&saddr.sin_addr.s_addr, 
		shost->h_length);

	saddr.sin_port = htons(portno);
	err = connect(sockfd, (struct sockaddr*) &saddr, sizeof(saddr));
	CHK_ERR(err, "ERROR socket: connecting");

	printf("=>[ ");
	memset(buffer, 0, 256);
	err = read(sockfd, buffer, 255);
	CHK_ERR(err, "ERROR read: reading from socket");
	printf("%s ]\n", buffer);
/*}}}*/

	/* sending plaintext */
	char *msg = argv[3];
	size_t dlen = strlen(msg);
	//if (dlen > 15 ) { dlen = 15; msg[15]='\0'; }
	buffer[0] = Crypt;
	buffer[1] = 0x0; buffer[2] = dlen;
	strcpy(&buffer[3], msg);
	err = write(sockfd, buffer, dlen+4);
	CHK_ERR(err, "ERROR write: writing plaintext to socket");
	printf("<=[ %s ]\n", msg);

	/* response */
	printf("=>[");
	memset(buffer, 0, 256);
	err = read(sockfd, buffer, 255);
	CHK_ERR(err, "ERROR socket: reading from socket");
	if(buffer[0] == Cryptd) printf("c: ");
	for(int i=0;i<16;i++) printf("%hhx", buffer[i+3]);
	printf(" ]\n");
	
	/* sending ciphertext */
	printf("<=[ ");
	buffer[0] = Decrypt;
	dlen = nhgets(&buffer[1]);
	printf("(%ld)", dlen);
	err =  write(sockfd, buffer, dlen+3);
	CHK_ERR(err, "ERROR socket: writing cipher to socket");
	for(int i=0;i<16;i++) printf("%hhx", buffer[i+3]);
	printf(" ]\n");

	/* response */
	printf("=>[");
	memset(buffer, 0, 256);
	err = read(sockfd, buffer, 255);
	CHK_ERR(err, "ERROR socket: reading from socket");
	if(buffer[0] == Decryptd) printf("d: ");
	printf("%s ]\n", buffer+3);

/*FIN{{{*/
	puts("cleaning up");
	close(sockfd);
	return 0;
/*}}}*/
}
