#!/bin/bash

function cleanup() {
    pkill -SIGKILL server
    kill $ZIG_SERVER_PID
    echo "exit"
}

trap cleanup EXIT

TEST_CIPHER_SUITES=(
    "TLS_AES_128_GCM_SHA256"
    "TLS_AES_256_GCM_SHA384"
    "TLS_CHACHA20_POLY1305_SHA256"
)

set -eux

cd $(dirname $0)

cd test
# Generate testing certificate
./gen_cert.sh

cd ../

# Stream
for SUITE in "${TEST_CIPHER_SUITES[@]}"
do
    echo "Testing Stream $SUITE."
    cd test

    # Run openssl server
    ./go/server &

    cd ../

    set +e

    # Let's test!
    zig run src/test_stream.zig -O ReleaseSafe -- 1038000 1048576
    if [ $? -ne 0 ]; then
        echo "failed."
        exit 1
    fi
    echo "OK."

    set -e

    pkill -SIGKILL server

    sleep 1
done

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