#!/bin/bash

#openssl req -x509 -nodes -days 365 -subj '/C=JP/ST=Osaka/L=Kyoto/CN=example.com' -newkey rsa:2048 -keyout prikey.pem -out cert.pem
openssl req -x509 -nodes -days 365 -subj '/C=JP/ST=Kyoto/L=Kyoto/CN=localhost' -newkey ec:<(openssl ecparam -name prime256v1) -nodes -sha256 -keyout prikey.pem -out cert.pem
openssl x509 -text -noout -in cert.pem
openssl x509 -outform der -in cert.pem -out cert.der
openssl ec -outform der -in prikey.pem -out prikey.der
#openssl x509 -outform der -in cert.pem -out cert.der
#hexdump cert.der -v -e '13/1 "0x%02x, "' -e '"\n"'