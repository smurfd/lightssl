cat >> build/ca.cnf <<EOL
[ req ]
encrypt_key = no
utf8 = yes
string_mask = utf8only
prompt = no
distinguished_name = root_dn
x509_extensions = extensions

[ root_dn ]
countryName = SE
0.organizationName = smurfin test
commonName = Root CA

[ extensions ]
keyUsage = critical,keyCertSign,cRLSign
basicConstraints = critical,CA:TRUE
subjectKeyIdentifier = hash
EOL

openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 \
  -config build/ca.cnf -keyout build/ca.key -out build/ca.crt &> /dev/null

openssl x509 -in build/ca.crt -text -noout &> /dev/null
