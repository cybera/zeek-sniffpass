#!/bin/bash
sudo tcpdump -i ens3 -w http_post.trace port 80 &
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=username1@example.com&password=password1" http://portquiz.net
curl -X POST -H "CoNtEnT-tYpE: application/x-wWW-fOrM-UrLEnCoDeD" -d "log=username2@example.com&pass=password2" http://portquiz.net
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "LOG=username3@example.com&pass=password3" http://portquiz.net
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "pass=password4&username=username4" http://portquiz.net
sleep 5
sudo pkill tcpdump
