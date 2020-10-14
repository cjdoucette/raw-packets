#!/bin/bash
sudo tcpdump -i ens5 -n src 172.31.0.197 and not port 22 > legit_log.txt &
sleep 2
for i in {1..100}
do
	if (($i % 100)); then
		echo $i
	fi
	#nc -N -w 10 172.31.3.200 1234 < file.dat
	curl --max-time 10 -F 'file=@/home/ubuntu/output.dat' http://172.31.3.200:44444/
done
sleep 2
sudo pkill tcpdump
