.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl

all: client server keys

clean:
	rm -f server client *.o chat.db 
	rm -rf test-tmp clientkeys serverkeys ttpkeys

ui.o: ui.c ui.h

client.o: client.c api.h ui.h util.h cmd.h db-stuff.h 

api.o: api.c api.h 

server.o: server.c util.h

util.o: util.c util.h

crypto.o: crypto.c crypto.h

ttp.o: ttp.c ttp.h

worker.o: worker.c util.h worker.h

client: client.o api.o ui.o util.o ssl-nonblock.o crypto.o ttp.o

server: server.o api.o util.o worker.o ssl-nonblock.o crypto.o ttp.o

ssl-nonblock.o: ssl-nonblock.c ssl-nonblock.h

keys:
	mkdir -p "clientkeys" "serverkeys" "ttpkeys"
# set up CA
	openssl genrsa -out ttpkeys/ca-key.pem 2>/dev/null
	openssl req -new -x509 -key ttpkeys/ca-key.pem -out ttpkeys/ca-cert.pem -nodes -subj '/C=NL/ST=NH/CN=CA/emailAddress=a.soleimani@student.vu.nl' 2>/dev/null
# copy CA cert in clientkeys
	cp ttpkeys/ca-cert.pem clientkeys/
# create CA-signed certificate for server
	openssl genrsa -out serverkeys/server-key.pem 2>/dev/null
	openssl req -new -key serverkeys/server-key.pem -out serverkeys/server-csr.pem -nodes -subj '/CN=server\group 18/' 2>/dev/null
	openssl x509 -req -CA ttpkeys/ca-cert.pem -CAkey ttpkeys/ca-key.pem -CAcreateserial -in serverkeys/server-csr.pem -out serverkeys/server-ca-cert.pem 2>/dev/null