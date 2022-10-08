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

zig test src/test_stream_server.zig --test-filter 'stream' &
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
