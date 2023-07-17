#!/bin/bash

set -x 

export KERBEROS_USERNAME="vscode"
export KERBEROS_PASSWORD="vscode"
export KERBEROS_REALM="vscode.proxy.test"
export KERBEROS_PORT="80"
export KERBEROS_HOSTNAME="test-http-kerberos-proxy"

echo "Setting up Kerberos config file at /etc/krb5.conf"
cat > /etc/krb5.conf << EOL
[libdefaults]
    default_realm = ${KERBEROS_REALM^^}
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    ${KERBEROS_REALM^^} = {
        kdc = $KERBEROS_HOSTNAME
        admin_server = $KERBEROS_HOSTNAME
    }
[domain_realm]
    .$KERBEROS_REALM = ${KERBEROS_REALM^^}
[logging]
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmin.log
    default = FILE:/var/log/krb5lib.log
EOL

echo -n "$KERBEROS_PASSWORD" | kinit "$KERBEROS_USERNAME"
