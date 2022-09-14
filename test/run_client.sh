#!/bin/bash

#openssl s_client -tls1_3 localhost:443
SSLKEYLOGFILE=/tmp/pre-master-secret.log curl https://localhost:8443 --insecure
