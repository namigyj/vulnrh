# vulnrh00
VERSION = 0.0

# libs & includes
LIBS = -lssl -lcrypto -lpthread
INCS = -I /usr/include/openssl

# flags
CFLAGS = -O3 -Wall -pedantic -DEBUG
VCFLAGS = $(INCS) $(CFLAGS)
VLFLAGS = $(LIBS)

# compiler
CC = c99
