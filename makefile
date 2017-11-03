# vulnrh - Very Unsercure Lacking [something] RaspeberryPi HSM

# if this makefile doesn't make any sense to you. That's normal.
# I do not know how to write a makefile. Credits go to __suckless.org__
# because I can atleast "hack" a makefile together based on their stuff.

include config.mk

SRC = vulnrh.c
OBJ = $(SRC:.c=.o)

all: options vulnrh

options: 
	@echo vulnrh build options:
	@echo "CFLAGS  = $(CFLAGS)"
	@echo "LDFLAGS = $(VLFLAGS)"
	@echo "CC      = $(CC)"

vulnrh.o: vulnrh.c

vulnrh: $(OBJ) 
	$(CC) $(VCFLAGS) -o $@ $(VLFLAGS) $^

clean: 
	rm -f vulnrh $(OBJ)

run: all
	./vulnrh

testclient.o: testclient.c

client: testclient.o
	$(CC) $(CFLAGS) -o $@ testclient.c
