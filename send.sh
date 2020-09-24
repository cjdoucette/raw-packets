#!/bin/bash
while true
do
	nc -w 0 -u -s 172.31.0.95 172.31.3.200 8080 <<< 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent volutpat tortor et suscipit mattis. Donec id ornare ligula, vitae vehicula nisi. Nulla tempus hendrerit urna volutpat vulputate velit.'
done
