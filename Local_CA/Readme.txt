#生成自签证书
openssl req -x509 -newkey rsa:2048 -keyout cakey.pem -out cacert.pem

#生成CA证书请求
openssl req -new -newkey rsa:2048 -out subca_req.pem -keyout subca_key.pem -config ./ca_openssl.cnf

#签发CA证书
openssl ca -in subca_req.pem -out subca_cert.pem -extensions v3_ca -config ./ca_openssl.cnf

#签发用户证书
openssl ca -in subca_req.pem -out subca_cert.pem -config ./ca_openssl.cnf
