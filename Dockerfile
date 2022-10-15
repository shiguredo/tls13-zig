FROM ubuntu:22.04

LABEL maintainer="naoki9911(Naoki MATSUMOTO) <m.naoki9911@gmail.com>"

# install build dependencies
RUN apt-get update && apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y openssl jq curl perl xz-utils bsdmainutils netcat

RUN mkdir /tls13-zig
COPY . /tls13-zig

RUN /tls13-zig/install_zig.sh
RUN patch -u /root/.local/zig-master/lib/std/os.zig /tls13-zig/os_send.patch
ENV PATH $PATH:/root/.local/zig-master

# Standby
CMD [/bin/bash -c 'while true; do sleep 1; done']