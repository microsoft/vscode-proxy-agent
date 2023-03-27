FROM ubuntu:latest

RUN apt-get update \
	&& apt-get install -y \
		privoxy \
		iputils-ping \
		dnsutils \
	&& rm -rf /var/lib/apt/lists/*

RUN sed -e 's/^listen-address/# \0/' -i /etc/privoxy/config
RUN echo "listen-address :8118" >>/etc/privoxy/config

CMD /etc/init.d/privoxy start && sleep inf
