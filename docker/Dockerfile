# wormhole proxy

FROM bashell/alpine-bash:latest
MAINTAINER Chaiwat Suttipongsakul "cwt@bashell.com"

RUN apk update && apk upgrade && apk add python3 && \
    cd / && pyvenv wormhole && /wormhole/bin/pip install \
    https://bitbucket.org/bashell-com/wormhole/get/default.tar.gz?`date | md5sum |cut -b -32`
ADD wormhole-forever.sh /wormhole/bin/

EXPOSE     8800/tcp
ENTRYPOINT ["/wormhole/bin/wormhole-forever.sh"]
