#!/bin/bash
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=foobar1@example.com&password=password1" http://portquiz.net
curl -X POST -H "CoNtEnT-tYpE: application/x-www-form-urlencoded" -d "log=foobar2@example.com&pass=password2" http://portquiz.net
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "LOG=foobar3@example.com&pass=password3" http://portquiz.net
curl -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "pass=password4&disisausername=username4" http://portquiz.net
