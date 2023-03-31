FROM mcr.microsoft.com/devcontainers/typescript-node:16-bullseye

RUN apt-get update \
	&& apt-get install -y \
		iputils-ping \
		dnsutils \
		libnss3-tools \
		chromium \
	&& rm -rf /var/lib/apt/lists/*

RUN wget "https://code.visualstudio.com/sha/download?build=insider&os=cli-alpine-$([ "`uname -m`" = "aarch64" ] && echo "arm64" || echo "x64")" -O- | tar -xz -C /usr/local/bin/
RUN mv /usr/local/bin/code-insiders /usr/local/bin/code-cli-insiders

ADD install-vscode.sh /root/
RUN /root/install-vscode.sh
ADD --chown=node:node ["settings.json", "/home/node/.config/Code - Insiders/User/settings.json"]

CMD sleep inf
