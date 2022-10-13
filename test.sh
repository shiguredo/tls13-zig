#!/bin/bash

TEST_CERT_ALGORITHM=(
    "prime256v1 sha256"
    "secp384r1 sha384"
)

TEST_CIPHER_SUITES=(
    "TLS_AES_128_GCM_SHA256"
    "TLS_AES_256_GCM_SHA384"
    "TLS_CHACHA20_POLY1305_SHA256"
)

TEST_GROUPS=(
    "x25519"
    "P-256"
)

set -eux

TMP_FIFO="/tmp/tls13-zig"
rm -rf $TMP_FIFO

mkfifo $TMP_FIFO

cd $(dirname $0)

for CERT_ALGO in "${TEST_CERT_ALGORITHM[@]}"
do

    # Generate testing certificate
    set -- $CERT_ALGO
    openssl req -x509 -nodes -days 365 -subj '/C=JP/ST=Kyoto/L=Kyoto/CN=localhost' -newkey ec:<(openssl ecparam -name $1) -nodes -$2 -keyout key.pem -out cert.pem
    openssl x509 -text -noout -in cert.pem

    for GROUP in "${TEST_GROUPS[@]}"
    do
        for SUITE in "${TEST_CIPHER_SUITES[@]}"
        do
            echo "Testing $GROUP-$SUITE(with cert $CERT_ALGO)."

            # Run openssl server
            openssl s_server -tls1_3 -accept 8443 -cert cert.pem -key key.pem -www -ciphersuites $SUITE -groups $GROUP &

            set +e

            # Let's test!
            NUM_OF_OK=`zig test src/main_test.zig --test-filter 'e2e with early_data'  2>&1 | grep "HTTP/1.0 200 ok" | wc -l`
            if [ $? -ne 0 ]; then
                echo "failed."
                pkill -SIGKILL openssl
                exit 1
            fi
            if [ $NUM_OF_OK -ne 2 ]; then
                echo "failed. NUM_OF_OK is not 2."
                pkill -SIGKILL openssl
                exit 1
            fi
            echo "OK."

            set -e

            pkill -SIGKILL openssl

            sleep 1
        done
    done

    # 0-RTT
    for SUITE in "${TEST_CIPHER_SUITES[@]}"
    do
        echo "Testing 0-RTT Early Data $SUITE(with cert $CERT_ALGO)."

        # Run openssl server
        cat $TMP_FIFO | openssl s_server -tls1_3 -accept 8443 -cert cert.pem -key key.pem -early_data -ciphersuites $SUITE &

        set +e

        # Let's test!
        zig test src/main_test_0rtt.zig --test-filter 'e2e with 0rtt'
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

done

rm -rf $TMP_FIFO
