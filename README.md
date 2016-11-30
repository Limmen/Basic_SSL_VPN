# VPN_LAB

## Run Server

`sudo cmake-build-debug/vpn_lab -i tun0 -s -d`

#### Setup IP for server

`sudo ip addr add 10.0.5.10/24 dev tun0`

`sudo ifconfig tun0 up`

## Run Client

`sudo cmake-build-debug/vpn_lab -i tun0 -c <ip of server> -d`

#### Setup IP for client

`sudo ip addr add 10.0.5.1/24 dev tun0`

`sudo ìfconfig tun0 up`

