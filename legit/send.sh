#!/bin/bash
sudo tcpdump -i ens5 'port 1234' -n > legit_log.txt &
sleep 2
for i in {1..1000}
do
	nc -N -w 1 172.31.3.200 1234 < file.dat
done
sleep 2
sudo pkill tcpdump
