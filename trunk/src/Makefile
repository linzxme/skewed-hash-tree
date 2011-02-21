CC=gcc
CFLAGS=-O2 -pipe -fomit-frame-pointer -Wall
LDFLAGS=-lcrypto -lm

all: merkle

merkle: main.o merkle.o utils.o
	$(CC) -o merkle $? $(LDFLAGS) $(CFLAGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

clean:
	rm -fr *.o merkle
