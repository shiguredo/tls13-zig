#!/bin/bash

set -eux

function cleanup() {
    set +e
    kill $ZIG_SERVER_PID
    echo "exit"
}

trap cleanup EXIT

cd $(dirname $0)

cd test
# Generate testing certificate
./gen_cert.sh

cd ../

# Checking memory leak
until nc -z localhost 8443; do sleep 1; done && curl https://localhost:8443 --insecure &
zig test src/main_test_server.zig --test-filter 'e2e server'
echo "Memory leak check passed"

zig run src/main_test_server.zig &
ZIG_SERVER_PID=$!

# wait for server becoming ready
until nc -z localhost 8443; do sleep 1; done

echo "READY"

curl https://localhost:8443 --tlsv1.3 --insecure | grep tls13-zig
if [ $? -eq 0 ]; then
    echo  "OK"
else
    echo "FAILED"
fi

# Testing Hello Retry Request
echo "GET / " | openssl s_client -groups x448:x25519 -servername localhost -connect localhost:8443 -ign_eof | grep tls13-zig
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "FAILED"
fi

echo "GET / " | openssl s_client -groups x448:secp256r1 -servername localhost -connect localhost:8443 -ign_eof | grep tls13-zig
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "FAILED"
fi

# Testing Resumption
echo "GET / " | openssl s_client -servername localhost -connect localhost:8443 -ign_eof -sess_out sess.pem | grep tls13-zig
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "FAILED"
fi

echo "GET / " | openssl s_client -servername localhost -connect localhost:8443 -ign_eof -sess_in sess.pem | grep tls13-zig
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "FAILED"
fi

# Testing Resumption with Hello Retry Request
echo "GET / " | openssl s_client -groups x448:x25519 -servername localhost -connect localhost:8443 -ign_eof -sess_out sess.pem | grep tls13-zig
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "FAILED"
fi

echo "GET / " | openssl s_client -groups x448:x25519 -servername localhost -connect localhost:8443 -ign_eof -sess_in sess.pem | grep tls13-zig
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "FAILED"
fi

# Testing 0-RTT Data
echo "GET / " > early_data.txt
RESULT=$(openssl s_client -servername localhost -connect localhost:8443 -ign_eof -sess_in sess.pem -early_data early_data.txt)
echo $RESULT | grep "Early data was accepted.*tls13-zig" > /dev/null
if [ $? -eq 0 ]; then
    echo "OK"
else
    echo "FAILED"
fi