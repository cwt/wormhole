# wormhole proxy

FROM quay.io/bashell/alpine-bash:latest

RUN apk update \
 && apk upgrade \
 && apk add python3 python3-dev musl-dev gcc make \
 && python3 -O -m venv /wormhole \
 && /wormhole/bin/pip install cython \
 && /wormhole/bin/pip install --compile uvloop \
 && /wormhole/bin/pip uninstall -y cython \
 && /wormhole/bin/pip install --compile wormhole-proxy \
 && apk del python3-dev musl-dev gcc make \
 && rm -rf /root/.cache /var/cache/apk/*

ADD wormhole-forever.sh /wormhole/bin/

EXPOSE     8800/tcp
ENTRYPOINT ["/wormhole/bin/wormhole-forever.sh"]

