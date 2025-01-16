
### Tests
Test server, in one terminal run
```
./build/debug/test_crypto_srv
```
Test client, in another terminal run
```
./build/debug/test_crypto_cli
```
Test hashing (SHA3-512)
```
./build/debug/test_hash3
```
Test hashing Shake
```
./build/debug/test_hash3_shake
```
Test keys (secp384r1)
```
./build/debug/test_keys
```
Test ciphers (AES)
```
./build/debug/test_ciphers
```
Test crypto (ASN.1)
```
./build/debug/test_crypto build/debug/ca.key build/debug/ca128.cms  #AES 128
./build/debug/test_crypto build/debug/ca.key build/debug/ca256.cms  #AES 256
```
