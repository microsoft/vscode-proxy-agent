#!/bin/bash
# Generates the CA used as the signing CA for the certificates Squid generates
# on the fly when bumping (intercepting) TLS connections, plus the localhost
# server certificate stunnel presents on the TLS proxy port. Both are signed by
# the same CA, so installing ca.crt in the host trust store covers everything.
# Idempotent: safe to run on every start.
set -e

SSL_DIR=/etc/squid/ssl
SSL_DB=/var/lib/squid/ssl_db

mkdir -p "$SSL_DIR"

if [ ! -f "$SSL_DIR/ca.crt" ] || [ ! -f "$SSL_DIR/ca.key" ]; then
	echo "Generating CA certificate ..."
	openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
		-keyout "$SSL_DIR/ca.key" \
		-out "$SSL_DIR/ca.crt" \
		-subj "/CN=Squid HTTPS Test CA" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign,cRLSign"
fi

# The localhost server certificate stunnel presents on the TLS proxy port.
if [ ! -f "$SSL_DIR/proxy.crt" ] || [ ! -f "$SSL_DIR/proxy.key" ]; then
	echo "Generating proxy server certificate ..."
	openssl req -new -newkey rsa:2048 -nodes \
		-keyout "$SSL_DIR/proxy.key" \
		-out "$SSL_DIR/proxy.csr" \
		-subj "/CN=localhost"
	# macOS (SecTrustEvaluateWithError) enforces Apple's TLS server cert policy:
	# leaf validity must be <= 398 days and the serverAuth EKU must be present,
	# otherwise the cert is rejected as "not standards compliant" (errSecCertificateNotStandardsCompliant / -67901).
	openssl x509 -req -in "$SSL_DIR/proxy.csr" \
		-CA "$SSL_DIR/ca.crt" -CAkey "$SSL_DIR/ca.key" -CAcreateserial \
		-out "$SSL_DIR/proxy.crt" -days 397 -sha256 \
		-extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")
	rm -f "$SSL_DIR/proxy.csr"
fi

# Squid drops privileges to the 'proxy' user, which must be able to read the key.
chmod 644 "$SSL_DIR/ca.crt" "$SSL_DIR/proxy.crt"
chmod 640 "$SSL_DIR/ca.key" "$SSL_DIR/proxy.key"
chgrp proxy "$SSL_DIR/ca.key" 2>/dev/null || true

# Initialize the database used to cache the per-host certificates Squid generates.
if [ ! -d "$SSL_DB" ]; then
	echo "Initializing SSL certificate database ..."
	mkdir -p "$(dirname "$SSL_DB")"
	/usr/lib/squid/security_file_certgen -c -s "$SSL_DB" -M 20MB
fi
chown -R proxy:proxy "$SSL_DB" 2>/dev/null || true

echo "CA certificate to install on the host: .devcontainer/squid-https-test/squid-ssl/ca.crt"
