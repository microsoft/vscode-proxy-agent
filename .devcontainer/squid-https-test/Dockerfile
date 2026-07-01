FROM ubuntu:latest

# squid-openssl is the Squid build with OpenSSL / SSL-Bump (TLS interception) support.
# stunnel provides the TLS-terminating proxy port in front of Squid.
RUN apt-get update \
	&& apt-get install -y \
		squid-openssl \
		stunnel4 \
		openssl \
		ca-certificates \
		iputils-ping \
		dnsutils \
	&& rm -rf /var/lib/apt/lists/*

COPY squid.conf /etc/squid/squid.conf
COPY stunnel.conf /etc/stunnel/stunnel.conf
COPY setup.sh /usr/local/bin/setup.sh
RUN chmod +x /usr/local/bin/setup.sh

CMD ["sleep", "inf"]
