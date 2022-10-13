#!/bin/bash

openssl s_client -connect localhost:8443 -servername localhost -tls1_3 -sess_out sess.pem
openssl s_client -connect localhost:8443 -servername localhost -tls1_3 -sess_in sess.pem
