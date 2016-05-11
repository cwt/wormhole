# wormhole proxy

FROM photon:latest
MAINTAINER Chaiwat Suttipongsakul "cwt@bashell.com"

RUN tdnf update -y && tdnf clean all
RUN tdnf install -y python3 python3-libs python3-tools python3-devel && tdnf clean all
RUN tdnf install -y autoconf automake binutils flex gawk gcc gdbm glibc-devel \
        libgcc-devel libgomp libgomp-devel libstdc++-devel libtool \
        linux-api-headers m4 make mpc mpfr perl sed && tdnf clean all && \
    pip3.5 install virtualenv && cd / && virtualenv wormhole && \
    /wormhole/bin/pip install cython && \
    /wormhole/bin/pip install uvloop && \
    /wormhole/bin/pip install wormhole-proxy && \
    tdnf remove -y autoconf automake binutils flex gawk gcc gdbm glibc-devel \
        libgcc-devel libgomp libgomp-devel libstdc++-devel libtool \
        linux-api-headers m4 make mpc mpfr perl sed && tdnf clean all && \
    rm -rf /root/.cache && \
    for cache in `find /wormhole -iname '__pycache__'`; do rm -rf $cache; done

ADD wormhole-forever.sh /wormhole/bin/

EXPOSE     8800/tcp
ENTRYPOINT ["/wormhole/bin/wormhole-forever.sh"]
