#!/bin/bash

TEST_CIPHER_SUITES=(
    "TLS_AES_128_GCM_SHA256"
    "TLS_AES_256_GCM_SHA384"
)

function kill_openssl() {
    set +e

    ps aux | grep openssl
    # Stop openssl server
    # NOTE: openssl s_server does not its kill child processes when it is killed.
    PIDS=$(ps ho pid --ppid=$1)
    kill $PIDS

    set -e
}

set -eux

cd $(dirname $0)

cd test
# Generate testing certificate
./gen_cert.sh

cd ../

for SUITE in "${TEST_CIPHER_SUITES[@]}"
do
    cd test

    # Run openssl server
    openssl s_server -tls1_3 -accept 8443 -cert cert.pem -key prikey.pem -www  -ciphersuites $SUITE &
    OPENSSL_SERVER_PID=$!

    cd ../

    # Let's test!
    zig run src/main_test.zig  2>&1 | grep "HTTP/1.0 200 ok"

    kill_openssl $OPENSSL_SERVER_PID

    sleep 1
done
