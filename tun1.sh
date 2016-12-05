#!/bin/bash

sudo ip addr add 10.0.5.10/24 dev tun0
sudo ifconfig tun0 up
