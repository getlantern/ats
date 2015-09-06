## Lantern chained server implemented using [Apache Traffic Server](http://trafficserver.apache.org/).

### Installation

```
sudo AUTH_TOKEN=xxx ./install.sh
gencert.py # from lantern_aws
#keytool -export -alias ats -keystore keystore.jks --storepass "Be Your Own Lantern" -rfc -file cert.pem # don't need this anymore
keytool -v -importkeystore -srckeystore keystore.jks -srcalias ats --srcstorepass "pass" -destkeystore keystore.p12 -deststoretype PKCS12 --deststorepass "pass"
openssl pkcs12 -in keystore.p12 -passin pass:"pass" -out key.pem -passout pass:"pass"
mv *.pem /etc/trafficserver
```
Lantern client must using the same auth token to access this chained server, and load the cert if it is using ssl.

### Development

Addition packages are required to compile the simple auth plugin

```
sudo apt-get -y install autoconf libtool pkg-config openssl tcl tcl-dev libxml2-dev libpcre3-dev
(cd ~; wget http://mirror.bit.edu.cn/apache/trafficserver/trafficserver-5.3.1.tar.bz2 && tar jxvf trafficserver-5.3.1.tar.bz2)
# To generate headers required by plugin
(cd ~/trafficserver-5.3.1 && autoreconf -if && ./configure --prefix=/opt/ts)
tsxs -I ~/trafficserver-5.3.1/lib/ts/ -o lantern-auth.so -c lantern-auth.c
```

Then you can run `install.sh` again to make the new plugin into effect.
