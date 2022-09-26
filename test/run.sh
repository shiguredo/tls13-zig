#!/bin/bash

#openssl s_server -tls1_3 -accept 443 -cert cert.pem -key prikey.pem -www
#openssl s_server -groups P-256 -tls1_3 -accept 443 -cert cert.pem -key prikey.pem -www
openssl s_server -tls1_3 -accept 8443 -cert cert.pem -key key.pem -www  -ciphersuites TLS_AES_128_GCM_SHA256 -groups secp256r1
