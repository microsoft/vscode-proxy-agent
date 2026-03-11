FROM node:20-slim

RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN npm init -y && npm install ws

COPY server.js .

CMD openssl req -nodes -x509 -newkey rsa:2048 -keyout /app/certs/ssl_key.pem -out /app/certs/ssl_cert.pem -days 365 -subj "/C=US/ST=Oregon/L=Portland/O=IT/CN=test-wss-server" -addext "subjectAltName=DNS:test-wss-server" \
    && node server.js

HEALTHCHECK --interval=1s --timeout=3s --retries=10 \
  CMD node -e "const https = require('https'); https.get('https://localhost:443', { rejectUnauthorized: false }, (res) => { process.exit(res.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"
