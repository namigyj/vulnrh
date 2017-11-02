#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define CHK_ERR(err,s) if ((err)==1) { printf("ERROR: "); perror(s); exit(1); }
