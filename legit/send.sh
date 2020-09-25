#!/bin/bash
sudo tcpdump -i ens5 '((tcp[tcpflags] == tcp-syn) or (tcp[tcpflags] == tcp-ack)) and port 1234' -n > output.txt &
#sudo tcpdump -i ens5 'port 1234' -n > output.txt &
sleep 2
for i in {1..1000}
do
	nc -N -w 1 172.31.3.200 1234 < file.dat
done
sleep 2
sudo pkill tcpdump
