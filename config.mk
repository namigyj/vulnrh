# vulnrh00
VERSION = 0.0

# libs & includes
LIBS = -lssl -lcrypto
INCS = -I /usr/include/openssl

# flags 
CFLAGS = -Wall -pedantic
VCFLAGS = $(INCS) $(CFLAGS)
VLFLAGS = $(LIBS)

# compiler
CC = c99
