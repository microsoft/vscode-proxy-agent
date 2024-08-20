FROM node:20

ENV DEBIAN_FRONTEND="noninteractive"

RUN apt-get update && apt-get -y -qq install \
  curl krb5-user

COPY ./configure-kerberos-client.sh /usr/local/bin/configure-kerberos-client.sh
