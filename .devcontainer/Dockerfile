FROM mcr.microsoft.com/devcontainers/typescript-node:16-bullseye

RUN apt-get update \
	&& apt-get install -y \
		iputils-ping \
		dnsutils \
	&& rm -rf /var/lib/apt/lists/*

ADD install-vscode.sh /root/
RUN /root/install-vscode.sh
