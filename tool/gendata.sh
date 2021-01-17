
YOUR_DOMAIN=${1:-lambdai.org}
DST_DIR=${2:-./data/}
mkdir $DST_DIR
# generate root ca 
openssl genrsa -out ${DST_DIR}root.key
openssl req -new -x509 -days 365 -key ${DST_DIR}root.key -out ${DST_DIR}root.crt \
-subj "/CN=root.YOUR_DOMAIN"

# generate server cert
openssl genrsa -out ${DST_DIR}server.key 
openssl req -new -key ${DST_DIR}server.key -out ${DST_DIR}server.csr \
-subj "/CN=server.$YOUR_DOMAIN"
openssl x509 -req -in ${DST_DIR}server.csr -days 3650 -sha256 -CAcreateserial -CA ${DST_DIR}root.crt -CAkey ${DST_DIR}root.key -out ${DST_DIR}server.crt

# generate client cert
openssl genrsa -out ${DST_DIR}client.key
openssl req -new -key ${DST_DIR}client.key -out ${DST_DIR}client.csr \
-subj "/CN=client.$YOUR_DOMAIN"
openssl x509 -req -in ${DST_DIR}client.csr -days 3650 -sha256 -CAcreateserial -CA ${DST_DIR}root.crt -CAkey ${DST_DIR}root.key -out ${DST_DIR}client.crt