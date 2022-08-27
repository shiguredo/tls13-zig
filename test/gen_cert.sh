#!/bin/bash

openssl req -x509 -nodes -days 365 -subj '/C=JP/ST=Osaka/L=Kyoto/CN=example.com' -newkey rsa:2048 -keyout prikey.pem -out cert.pem
#openssl req -x509 -nodes -days 365 -subj '/C=JP/ST=Kyoto/L=Kyoto/CN=example.com' -newkey ec:<(openssl ecparam -name prime258v1) -nodes -sha256 -keyout prikey.pem -out cert.pem
