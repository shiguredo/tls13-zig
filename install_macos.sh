#!/bin/bash

cd `dirname $0`

brew install openssl
brew install jq
echo 'PATH=/usr/local/opt/openssl/bin:$PATH' >> ~/.bashrc

./install_zig.sh