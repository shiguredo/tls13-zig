FROM ubuntu:22.04 AS tls13zig_base

LABEL maintainer="naoki9911(Naoki MATSUMOTO) <m.naoki9911@gmail.com>"

# install build dependencies
RUN apt-get update && apt-get upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y openssl jq curl perl xz-utils bsdmainutils netcat patch

RUN mkdir /tls13-zig
COPY . /tls13-zig

RUN /tls13-zig/install_zig.sh
ENV PATH $PATH:/root/.local/zig-master

# Standby
CMD [ "/bin/bash",  "-c",  "'while true; do sleep 1; done'" ]

FROM tls13zig_base AS tls13zig_proxy

WORKDIR /tls13-zig/examples/proxy
RUN zig build

CMD [ "/bin/bash",  "-c",  "'./zig-out/bin/proxy'" ]