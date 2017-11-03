#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define CHK_ERR(err,s) if (err==-1) { error(s) }
#define error(s) { perror(s); exit(1);}

void
test() {
	char buf[10];
	buf[0] = 'A'; buf[1] = 'B';
	strcpy(&buf[2], "test");
	puts(buf);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[]) {
	int sockfd, portno, err;
	struct sockaddr_in saddr;
	struct hostent *shost;
	char buffer[256];

	if ((argc == 2) && !(strcmp(argv[1], "test"))) {
		test();
	} else if (argc != 3) {
		fprintf(stderr, "usage %s hostname port\n", argv[0]);
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

	printf("waiting for hello packet");
	memset(buffer, 0, 256);
	err = read(sockfd, buffer, 255);
	CHK_ERR(err, "ERROR read: reading from socket");
	printf("OK\n=>[ %s ]\n", buffer);

	puts("cleaning up");
	close(sockfd);
	return 0;
}
