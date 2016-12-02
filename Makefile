INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	g++ -I$(INC) -L$(LIB) simpletun_udp.c -o simpletun_udp -lssl -lcrypto -ldl -fpermissive

clean:
	rm -rf *~ simpletun_udp