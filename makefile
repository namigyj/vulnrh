# vulnrh - Very Unsercure Lacking [something] RaspeberryPi HSM

include config.mk

SRC = vulnrh.c
OBJ = $(SRC:.c=.o)

all: options vulnrh

options: 
	@echo vulnrh build options:
	@echo "CFLAGS  = $(CFLAGS)"
	@echo "LDFLAGS = $(VLFLAGS)"
	@echo "CC      = $(CC)"

vulnrh.o : vulnrh.c

vulnrh: $(OBJ) 
	$(CC) $(VCFLAGS) -o $@ $(VLFLAGS) $^

clean: 
	rm -f vulnrh $(OBJ)

run: all
	./vulnrh
