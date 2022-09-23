#!/bin/bash

set -eux

function cleanup() {
    kill $ZIG_SERVER_PID
    echo "exit"
}

trap cleanup EXIT

cd $(dirname $0)

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