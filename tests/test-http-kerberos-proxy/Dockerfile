FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && \
    apt-get -y -qq install \
    python curl \
    build-essential libkrb5-dev \
    krb5-user krb5-kdc krb5-admin-server \
    apache2 libapache2-mod-auth-gssapi && \
    rm -rf /var/lib/apt/lists/*

COPY setup.sh /usr/local/bin/setup.sh

CMD ["/usr/local/bin/setup.sh"]
