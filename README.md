## Lantern chained server implemented by [Apache Traffic Server](http://trafficserver.apache.org/).

### Installation

```
sudo AUTH_TOKEN=xxx ./install.sh
```
Lantern client must using the same auth token to access this chained server.

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
