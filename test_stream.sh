#!/bin/bash

TEST_CIPHER_SUITES=(
    "TLS_AES_128_GCM_SHA256"
    "TLS_AES_256_GCM_SHA384"
    "TLS_CHACHA20_POLY1305_SHA256"
)

if [ $# == 1 ]; then
    TEST_CIPHER_SUITES=("$1")
fi

set -eux

TMP_FIFO="/tmp/tls13-zig"
rm -rf $TMP_FIFO

mkfifo $TMP_FIFO

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
    zig test src/test_stream.zig --test-filter "stream"
    if [ $? -ne 0 ]; then
        echo "failed."
        pkill -SIGKILL server
        exit 1
    fi
    echo "OK."

    set -e

    pkill -SIGKILL server

    sleep 1
done


rm -rf $TMP_FIFO
