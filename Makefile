.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl

all: client server

clean:
	rm -f server client *.o chat.db 
	rm -rf test-tmp

ui.o: ui.c ui.h

client.o: client.c api.h ui.h util.h cmd.h db-stuff.h 

api.o: api.c api.h 

server.o: server.c util.h

util.o: util.c util.h

crypto.o: crypto.c crypto.h

worker.o: worker.c util.h worker.h

client: client.o api.o ui.o util.o ssl-nonblock.o

server: server.o api.o util.o worker.o ssl-nonblock.o crypto.o

ssl-nonblock.o: ssl-nonblock.c ssl-nonblock.h

