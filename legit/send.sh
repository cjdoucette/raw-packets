#!/bin/bash
sudo tcpdump -i ens5 -n port 1234 > legit_log.txt &
sleep 2
for i in {1..100}
do
	if (($i % 100)); then
		echo $i
	fi
	nc -N -w 10 172.31.3.200 1234 < file.dat
done
sleep 2
sudo pkill tcpdump
