FROM ubuntu/squid:latest

RUN apt-get update \
    && apt-get install -y apache2-utils \
    && rm -rf /var/lib/apt/lists/*

COPY basic_auth.conf /etc/squid/conf.d/squid.acl.conf
RUN sed -e '/^http_access/ s/^#*/#/' -i /etc/squid/conf.d/debian.conf

ARG PROXY_USERNAME
ARG PROXY_PASSWORD
RUN htpasswd -bc /etc/squid/.htpasswd $PROXY_USERNAME $PROXY_PASSWORD
