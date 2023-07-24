#!/usr/bin/env bash

export KERBEROS_USERNAME="PlaceholderUsername"
export KERBEROS_PASSWORD="Placeholder"
export KERBEROS_REALM="vscode.proxy.test"
export KERBEROS_PORT="80"
export KERBEROS_HOSTNAME="test-http-kerberos-proxy.tests_test-proxies"

set -o xtrace
set -x

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

echo "Setting up kerberos ACL configuration at /etc/krb5kdc/kadm5.acl"
mkdir -p /etc/krb5kdc
echo -e "*/*@${KERBEROS_REALM^^}\t*" > /etc/krb5kdc/kadm5.acl

echo "Creating KDC database"
# krb5_newrealm returns non-0 return code as it is running in a container, ignore it for this command only
set +e
printf "$KERBEROS_PASSWORD\n$KERBEROS_PASSWORD" | krb5_newrealm
set -e

echo "Creating principals for tests"
kadmin.local -q "addprinc -pw $KERBEROS_PASSWORD $KERBEROS_USERNAME"

echo "Adding principal for Kerberos auth and creating keytabs"
kadmin.local -q "addprinc -randkey HTTP/$KERBEROS_HOSTNAME"
kadmin.local -q "ktadd -k /etc/krb5.keytab HTTP/$KERBEROS_HOSTNAME"

chmod 777 /etc/krb5.keytab

echo "Restarting Kerberos KDS service"
service krb5-kdc restart

echo "Add ServerName to Apache config"
grep -q -F "ServerName $KERBEROS_HOSTNAME" /etc/apache2/apache2.conf || echo "ServerName $KERBEROS_HOSTNAME" >> /etc/apache2/apache2.conf

echo "Deleting default virtual host files"
rm /etc/apache2/sites-enabled/*.conf
rm /etc/apache2/sites-available/*.conf

echo "Create virtual host files"
cat > /etc/apache2/sites-available/kerberos-proxy.conf << EOL
<VirtualHost *:$KERBEROS_PORT>
    ServerName $KERBEROS_HOSTNAME
    ServerAlias $KERBEROS_HOSTNAME

    ProxyRequests On
    ProxyPreserveHost On

    <Proxy *>
        Order Deny,Allow
        Allow from all

        AuthType GSSAPI
        AuthName "GSSAPI Single Sign On Login"
        Require valid-user
        GssapiCredStore keytab:/etc/krb5.keytab
    </Proxy>

</VirtualHost>
EOL

echo "Enabling virtual host site"
a2ensite kerberos-proxy.conf

echo "Enabling apache modules"
a2enmod proxy
a2enmod proxy_http
a2enmod proxy_http2
a2enmod proxy_connect
a2enmod ssl
a2enmod headers
service apache2 restart

echo "KERBEROS PROXY RUNNING"
# show apache logs to keep container running
tail -f /var/log/apache2/error.log