# debug
mkdir -p `pwd`/build/debug/ 
echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes128 -secretkey 31337DEADBEEF666999ABCDEF31337FF -outform der > `pwd`/build/debug/ca128.cms
echo "66612345678966601234567890666" | openssl cms -EncryptedData_encrypt -aes256 -secretkey 31337DEADBEEF666999ABCDEF31337FF31337DEADBEEF666999ABCDEF31337FF -outform der > `pwd`/build/debug/ca256.cms

openssl ecparam -name secp384r1 -genkey -noout -out `pwd`/build/debug/ca.key
