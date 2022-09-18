#!/bin/bash

TEST_CIPHER_SUITES=(
    "TLS_AES_128_GCM_SHA256"
    "TLS_AES_256_GCM_SHA384"
)

set -eu

cd $(dirname $0)

cd test
# Generate testing certificate
./gen_cert.sh

cd ../

for SUITE in "${TEST_CIPHER_SUITES[@]}"
do
    echo "Testing $SUITE."
    cd test

    # Run openssl server
    openssl s_server -tls1_3 -accept 8443 -cert cert.pem -key prikey.pem -www  -ciphersuites $SUITE &

    cd ../

    set +e

    # Let's test!
    zig run src/main_test.zig  2>&1 | grep "HTTP/1.0 200 ok"
    if [ $? -ne 0 ]; then
        echo "failed."
        pkill -SIGKILL openssl
        exit 1
    fi
    echo "OK."

    set -e

    pkill -SIGKILL openssl

    sleep 1
done
