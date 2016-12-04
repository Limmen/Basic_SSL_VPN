INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	g++ -I$(INC) -L$(LIB) simpletun_encryption_udp.c ssl_util.c server.c client.c tunnel_util.c parse_input.c util.c -o simpletun_encryption_udp -lssl -lcrypto -ldl -fpermissive

clean:
	rm -rf *~ simpletun_encryption_udp