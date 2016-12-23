# Simple VPN Tunnel in C using OpenSSL

## Commands

### Compile and build

`make`

### Server

#### Start VPN

`./simpletun_encryption_udp -i tun0 -s -r <remote ip> -d -p <port>`

#### Sample setup of tun/tap interface

`./tun.sh`

### Client

#### Connect to Server VPN

`./simpletun_encryption_udp -i tun0 -i -r <remote ip> -d -p <port>`

#### Sample setup of tun/tap interface

`./tun1.sh`

### Notes
passphrase server cert: "server"

passphrase client cert: "client"

default port for TCP server channel: `4433`


#Authors

Kim Hammar

Konstantin Sozinov