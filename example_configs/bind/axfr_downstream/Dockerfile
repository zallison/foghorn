FROM debian:stable-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends bind9 bind9-utils \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/bind/zones

COPY named.conf /etc/bind/named.conf
COPY zones/ /etc/bind/zones/

EXPOSE 53/tcp 53/udp

CMD ["named", "-g", "-u", "bind", "-c", "/etc/bind/named.conf"]
