INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	g++ -I$(INC) -L$(LIB) simpletun_udp.c ssl_util.c server.c client.c -o simpletun_udp -lssl -lcrypto -ldl -fpermissive

clean:
	rm -rf *~ simpletun_udp