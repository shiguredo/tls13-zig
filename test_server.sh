#!/bin/bash

set -eux

function cleanup() {
    kill $ZIG_SERVER_PID
    echo "exit"
}

trap cleanup EXIT

cd $(dirname $0)

cd test
# Generate testing certificate
./gen_cert.sh

cd ../

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

kill -SIGKILL $ZIG_SERVER_PID

zig run src/test_stream_server.zig &
ZIG_SERVER_PID=$!

cd test

set +e

# wait for server becoming ready
until nc -z localhost 8443; do sleep 1; done

# Let's test!
./go/client  1048000 1048576
if [ $? -ne 0 ]; then
    echo "failed."
    exit 1
fi
echo "OK."

set -e
