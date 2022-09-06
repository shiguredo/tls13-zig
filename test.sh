#!/bin/bash

set -eux

cd $(dirname $0)

cd test
# Generate testing certificate
./gen_cert.sh
# Run openssl server
./run.sh &
OPENSSL_SERVER_PID=$!

cd ../

# Let's test!
zig run src/main.zig  2>&1 | grep "HTTP/1.0 200 ok"

set +e

ps aux | grep openssl
# Stop openssl server
# NOTE: openssl s_server does not its kill child processes when it is killed.
kill $(ps ho pid --ppid=$OPENSSL_SERVER_PID)
ps aux | grep openssl
