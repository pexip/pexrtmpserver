#!/usr/bin/env bash

set -e

# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -subj '/O=TestCA/CN=Test' -days 3650 -out ca.pem -extensions v3_ca

cat >rtmp.cnf <<EOF
[ cert_no_san ]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ cert_with_san ]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:localhost,IP:127.0.0.1

[ cert_bad_san ]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:invalid,IP:255.255.255.255
EOF

openssl genrsa -out cert.key 4096

openssl req -new -key cert.key -subj "/O=Pexip/CN=localhost" -days 3650 -out rtmp.csr
openssl x509 -req -days 3650 -in rtmp.csr -CA ca.pem -CAkey ca.key -extfile rtmp.cnf -extensions cert_no_san -set_serial 01 -out cert_cn_dns.pem

openssl req -new -key cert.key -subj "/O=Pexip/CN=127.0.0.1" -days 3650 -out rtmp.csr
openssl x509 -req -days 3650 -in rtmp.csr -CA ca.pem -CAkey ca.key -extfile rtmp.cnf -extensions cert_no_san -set_serial 01 -out cert_cn_ip.pem

openssl req -new -key cert.key -subj "/O=Pexip/CN=use-san" -days 3650 -out rtmp.csr
openssl x509 -req -days 3650 -in rtmp.csr -CA ca.pem -CAkey ca.key -extfile rtmp.cnf -extensions cert_with_san -set_serial 01 -out cert_san.pem

openssl req -new -key cert.key -subj "/O=Pexip/CN=use-san" -days 3650 -out rtmp.csr
openssl x509 -req -days 3650 -in rtmp.csr -CA ca.pem -CAkey ca.key -extfile rtmp.cnf -extensions cert_bad_san -set_serial 01 -out cert_san_mismatch.pem

rm rtmp.csr
rm rtmp.cnf
