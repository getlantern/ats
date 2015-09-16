#! /usr/bin/env sh

PREFIX=/opt/ts
PLUGIN_DIR=$PREFIX/libexec/trafficserver
CONFIG_DIR=$PREFIX/etc/trafficserver

if [ -z "$AUTH_TOKEN" ]; then
	echo 'Missing AUTH_TOKEN environment variable' && exit 1;
fi

if [ -z "$CERT_FILE" ]; then
	echo 'Missing CERT_FILE environment variable' && exit 1;
fi

if [ -z "$CERT_PASS" ]; then
	echo 'Missing CERT_PASS environment variable' && exit 1;
fi

if [ ! -r "$CERT_FILE" ]; then
	echo "$CERT_FILE does not exist or is not readable" && exit 1;
fi

echo 'Installing package...'
mkdir -p $PREFIX
curl -L https://s3.amazonaws.com/lantern-aws/apache-traffic-server-5.3.1-ubuntu-14-64bit.tar.gz | tar zxC $PREFIX
echo 'Copying plugin and cert...'
cp ./lantern-auth.so $PLUGIN_DIR/
cp $CERT_FILE $CONFIG_DIR/
echo 'Changing configuration...'
echo "$PLUGIN_DIR/lantern-auth.so $AUTH_TOKEN" > $CONFIG_DIR/plugin.config
echo "dest_ip=* ssl_cert_name=key.pem ssl_key_dialog=\"exec:/bin/echo $CERT_PASS\"" > $CONFIG_DIR/ssl_multicert.config
cp ./records.config $CONFIG_DIR/
cp ./remap.config $CONFIG_DIR/
# sed -i 's/\(CONFIG proxy.config.url_remap.remap_required INT\) 1/\1 0/' $PREFIX/etc/trafficserver/records.config
# sed -i 's/\(CONFIG proxy.config.http.cache.http INT \) 0/\1 1/' $PREFIX/etc/trafficserver/records.config
# sed -i 's/\(CONFIG proxy.config.reverse_proxy.enabled INT \) 1/\1 0/' $PREFIX/etc/trafficserver/records.config
# sed -i 's/\(CONFIG proxy.config.http.insert_squid_x_forwarded_for INT \) 0/\1 1/' $PREFIX/etc/trafficserver/records.config
# sed -i 's/\(CONFIG proxy.config.http.connect_ports STRING 443 563\)/\1 80 8080 8443 8563 8226/' $PREFIX/etc/trafficserver/records.config
echo 'Starting service...'
$PREFIX/bin/trafficserver start
