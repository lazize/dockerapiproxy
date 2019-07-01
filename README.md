# Docker API Proxy
Proxy server to expose Docker API with LDAP authentication and restriction rules

## How to get, compile and run

```shell
go get github.com/lazize/dockerapiproxy
cd $GOPATH/dockerapiproxy
go build
# Fix password on file "dockerapiproxy.conf"
./dockerapiproxy
```
