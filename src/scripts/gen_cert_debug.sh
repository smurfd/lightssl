# debug
openssl req -x509 -sha256 -days 3650 -newkey rsa:4096 \
  -config `pwd`/build/ca.cnf -keyout `pwd`/build/debug/ca.key -out `pwd`/build/debug/ca.crt &> /dev/null

openssl x509 -in `pwd`/build/debug/ca.crt -text -noout &> /dev/null

echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes128 -secretkey 31337DEADBEEF666999ABCDEF31337FF -outform der > `pwd`/build/debug/ca128.cms
echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes256 -secretkey 31337DEADBEEF666999ABCDEF31337FF31337DEADBEEF666999ABCDEF31337FF -outform der > `pwd`/build/debug/ca256.cms

openssl ecparam -name secp384r1 -genkey -noout -out `pwd`/build/debug/secp384r1-key.pem
