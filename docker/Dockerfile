# wormhole proxy

FROM bashell/alpine-bash:latest
MAINTAINER Chaiwat Suttipongsakul "cwt@bashell.com"

RUN apk update && apk upgrade && apk add python3
RUN apk add python3-dev musl-dev gcc make && \
    cd / && pyvenv-3.5 wormhole && \
    /wormhole/bin/pip install cython && \
    /wormhole/bin/pip install uvloop && \
    /wormhole/bin/pip uninstall -y cython && \
    /wormhole/bin/pip install wormhole-proxy && \
    apk del python3-dev musl-dev gcc make && \
    rm -rf /root/.cache && rm -rf /var/cache/apk/* && \
    for cache in `find /wormhole -iname '__pycache__'`; do rm -rf $cache; done

ADD wormhole-forever.sh /wormhole/bin/

EXPOSE     8800/tcp
ENTRYPOINT ["/wormhole/bin/wormhole-forever.sh"]
