# wormhole proxy

FROM bashell/alpine-bash:latest
MAINTAINER Chaiwat Suttipongsakul "cwt@bashell.com"

RUN apk update && apk upgrade && apk add python3
COPY wormhole.py /usr/bin

EXPOSE     8800/tcp
ENTRYPOINT ["/usr/bin/python3", "-O", "/usr/bin/wormhole.py"]
CMD        ["--help"]
