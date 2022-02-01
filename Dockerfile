FROM alpine:latest

LABEL maintainer="docker@doowan.net"

RUN apk -Uuv add bash \
                 cargo \
                 curl-dev \
                 gcc \
                 libffi-dev \
                 libmagic \
                 libressl-dev \
                 musl-dev \
                 python3 \
                 python3-dev \
                 py3-magic \
                 py3-pip && \
    find /var/cache/apk/ -type f -delete

RUN pip3 install nsaproxy

ADD docker-run.sh /run.sh
ADD etc/nsaproxy/modules /etc/nsaproxy/modules
ADD etc/nsaproxy/rrsets /etc/nsaproxy/rrsets

EXPOSE 8670/tcp

CMD ["/run.sh"]
