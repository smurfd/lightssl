mkdir -p build/debug build/release
chmod -R +w build/
cat >> `pwd`/build/ca.cnf <<EOL
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
