# vulnrh - Very Unsercure Lacking [something] RaspeberryPi HSM

# if this makefile doesn't make any sense to you. That's normal.
# I do not know how to write a makefile. Credits go to __suckless.org__
# because I can atleast "hack" a makefile together based on their stuff.

include config.mk

SRC = src/vulnrh.c
OBJ = $(SRC:.c=.o)

all: options vulnrh

options:
	@echo vulnrh build options:
	@echo "CFLAGS  = $(CFLAGS)"
	@echo "LDFLAGS = $(VLFLAGS)"
	@echo "CC      = $(CC)"

vulnrh.o: vulnrh.c

vulnrh: $(OBJ)
	$(CC) $(VCFLAGS) -o bin/$@ $(VLFLAGS) $^

clean:
	rm -f bin/vulnrh $(OBJ)
	rm -f bin/client src/testclient.o

run: all
	./bin/vulnrh

testclient.o: testclient.c

client: src/testclient.o
	$(CC) -o bin/$@ src/testclient.c
