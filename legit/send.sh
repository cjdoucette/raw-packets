#!/bin/bash
sudo tcpdump -i ens5 -n src 172.31.0.150 and not port 22 | sudo tee legit_log.txt > /dev/null &
sleep 2
for i in {1..50}
do
	if (($i % 100)); then
		echo $i
	fi
	#nc -N -w 10 172.31.3.200 1234 < file.dat
	#curl --connect-timeout 20 --max-time 20 -F 'file=@/home/ubuntu/output.dat' http://172.31.3.200:44444/
	curl -F 'file=@/home/ubuntu/output.dat' http://172.31.3.200:44444/
done
sleep 2
sudo pkill tcpdump
