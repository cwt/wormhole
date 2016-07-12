# wormhole proxy

FROM bashell/alpine-bash:latest
MAINTAINER Chaiwat Suttipongsakul "cwt@bashell.com"

RUN apk update && apk upgrade && apk add python3
RUN cd / && pyvenv-3.5 wormhole && \
    /wormhole/bin/pip install wormhole-proxy && \
    rm -rf /root/.cache && rm -rf /var/cache/apk/* && \
    for cache in `find /wormhole -iname '__pycache__'`; do rm -rf $cache; done

ADD wormhole-forever.sh /wormhole/bin/

EXPOSE     8800/tcp
ENTRYPOINT ["/wormhole/bin/wormhole-forever.sh"]
