
Compile and build: make

run:

Server

./simpletun_encryption_udp -i tun0 -s -r <remote ip> -d -p <port>

Client

./simpletun_encryption_udp -i tun0 -i -r <remote ip> -d -p <port>


passphrase server cert: "server"
passphrase client cert: "client"

default port for TCP server channel: 4433



Authors

Kim Hammar

Konstantin Sozinov


