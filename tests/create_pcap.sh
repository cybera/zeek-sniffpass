#!/bin/bash
python3 -m http.server --bind 127.0.0.1 8080 &
PYHTTP_PID=$!
sudo tcpdump -i lo -w http_post.trace port 8080 &
TCPDUMP_PID=$!
sleep 5
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=username1@example.com&password=password1" http://127.0.0.1:8080 &
curl -X POST -H "CoNtEnT-tYpE: application/x-wWW-fOrM-UrLEnCoDeD" -d "log=username2@example.com&pass=password2" http://127.0.0.1:8080 &
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "LOG=username3@example.com&pass=password3" http://127.0.0.1:8080 &
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "pass=password4&username=username4" http://127.0.0.1:8080 &
curl -X GET http://127.0.0.1:8080/?pass=password5&username=username5 &
sleep 10
kill ${PYHTTP_PID}
sleep 5
sudo pkill -9 tcpdump
