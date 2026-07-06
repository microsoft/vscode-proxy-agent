FROM ubuntu/squid:latest

COPY open.conf /etc/squid/conf.d/squid.acl.conf
RUN sed -e '/^http_access/ s/^#*/#/' -i /etc/squid/conf.d/debian.conf
