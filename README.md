## Lantern chained server implemented using [Apache Traffic Server](http://trafficserver.apache.org/).

### Installation

Prerequisites

```
sudo apt-get update
sudo apt-get install -y git libtool tcl openjdk-7-jre-headless openssl
```


Be sure to generate private key along with certificate before install ATS.

```
CERT_PASS=MY_VERY_OWN_PASSWORD
IP=`ifconfig eth0 | grep "inet addr" | awk -F ':' '{print $2}' | awk '{print $1}'`
keytool -genkeypair -keystore keystore.jks -alias ats -keypass "$CERT_PASS" -storepass "$CERT_PASS" -ext san=ip:$IP -dname 'CN=Seacoasts Furtwngler, O=Poising Parched, L=Bin, S=California, C=US' -startdate -3m-27d -keyalg RSA -keysize 2048 -validity 730
keytool -v -importkeystore -srckeystore keystore.jks -srcalias ats --srcstorepass "$CERT_PASS" -destkeystore keystore.p12 -deststoretype PKCS12 --deststorepass "$CERT_PASS"
openssl pkcs12 -in keystore.p12 -passin pass:"$CERT_PASS" -out key.pem -passout pass:"$CERT_PASS" # key.pem will be used by ATS
keytool -export -alias ats -keystore keystore.jks --storepass "$CERT_PASS" -rfc -file cert.pem # cert.pem will be the in chained server config
```

Then install the chained server powered by ATS

```
git clone https://github.com/getlantern/ats
cd ats
sudo AUTH_TOKEN=xxx CERT_FILE=<path of key.pem> CERT_PASS=xxx ./install.sh
```

Finaly, configure your Lantern client to use this server

```
  chainedservers:
    fallback-192.241.211.121:
      addr: 192.241.211.121:443
      pipelined: true
      cert: "<content of cert.pem here>"
      authtoken: "<AUTH_TOKEN here>"
      weight: 1000000
      qos: 10
      trusted: true
```

### Development

The simple auth plugin, lantern-auth.so, is built on a 64bit Ubuntu 14.10 box. Addition packages are required to compile it.

```
sudo apt-get -y install autoconf libtool pkg-config libssl-dev tcl-dev libxml2-dev libpcre3-dev
(cd ~; wget http://mirror.bit.edu.cn/apache/trafficserver/trafficserver-5.3.1.tar.bz2 && tar jxvf trafficserver-5.3.1.tar.bz2)
# To generate headers required by plugin
(cd ~/trafficserver-5.3.1 && autoreconf -if && ./configure --prefix=/opt/ts)
tsxs -I ~/trafficserver-5.3.1/lib/ts/ -o lantern-auth.so -c lantern-auth.c
```

Then you can run `install.sh` again to take the new plugin into effect.
