#! /usr/bin/env sh

PLUGIN_DIR=/usr/local/libexec/trafficserver

if [ -z "$AUTH_TOKEN" ]; then
	echo 'Missing AUTH_TOKEN environment variable' && exit 1;
fi

echo 'Installing package...'
apt-get install -q=2 -y trafficserver
echo 'Copying plugin...'
cp `pwd`/lantern-auth.so $PLUGIN_DIR/
echo 'Change configuration...'
echo "$PLUGIN_DIR/lantern-auth.so $AUTH_TOKEN" > /etc/trafficserver/plugin.config
sed -i 's/\(CONFIG proxy.config.url_remap.remap_required INT\) 1/\1 0/' /etc/trafficserver/records.config
sed -i 's/\(CONFIG proxy.config.http.cache.http INT \) 0/\1 1/' /etc/trafficserver/records.config
sed -i 's/\(CONFIG proxy.config.reverse_proxy.enabled INT \) 1/\1 0/' /etc/trafficserver/records.config
echo 'Restarting service...'
service trafficserver restart