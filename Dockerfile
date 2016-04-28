# wormhole proxy

FROM bashell/alpine-bash:latest
MAINTAINER Chaiwat Suttipongsakul "cwt@bashell.com"

RUN apk update && apk upgrade && apk add python3 && \
    cd / && pyvenv wormhole && \
    /wormhole/bin/pip install https://bitbucket.org/bashell-com/wormhole/get/multi_files.tar.gz

EXPOSE     8800/tcp
ENTRYPOINT ["/wormhole/bin/wormhole"]

