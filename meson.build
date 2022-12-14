project('lightssl', 'c', version : '0.1', default_options :
  ['warning_level=3', 'c_std=c99'])

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : true)
p_dep = cc.find_library('pthread', required : true)
thread_dep = dependency('threads', required : true)

build_args = [
  '-Wno-unused-variable',
  '-Wno-unused-function',
  '-Wall',
  '-Wextra',
  '-Wno-unused-parameter',
  '-pedantic',
  '-O2',
  '-pthread']

liblighthash = static_library('lighthash', 'src/lighthash.c')
liblighthash3 = static_library('lighthash3', 'src/lighthash3.c')
liblightkeys = static_library('lightkeys', 'src/lightkeys.c')
liblightcrypto = static_library('lightcrypto', 'src/lightcrypto.c',
  link_args: '-pthread',
  dependencies: [m_dep, p_dep],
  c_args: build_args)
liblightciphers = static_library('lightciphers', 'src/lightciphers.c')

test_lightcrypto = executable('test_lightcrypto', 'src/tests/test_lightcrypto.c',
  link_with: [liblightcrypto],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lightcrypto_cli = executable('test_lightcrypto_cli', 'src/tests/test_lightcrypto_cli.c',
  link_with: [liblightcrypto],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lightcrypto_srv = executable('test_lightcrypto_srv', 'src/tests/test_lightcrypto_srv.c',
  link_with: [liblightcrypto],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lightciphers = executable('test_lightciphers', 'src/tests/test_lightciphers.c',
  link_with: [liblightciphers],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lightkeys = executable('test_lightkeys', 'src/tests/test_lightkeys.c',
  link_with: [liblightkeys],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash3 = executable('test_lighthash3', 'src/tests/test_lighthash3.c',
  link_with: [liblighthash3],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_sha0 = executable('test_lighthash_sha0', 'src/tests/test_lighthash_sha0.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_sha1 = executable('test_lighthash_sha1', 'src/tests/test_lighthash_sha1.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_sha2 = executable('test_lighthash_sha2', 'src/tests/test_lighthash_sha2.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_sha3 = executable('test_lighthash_sha3', 'src/tests/test_lighthash_sha3.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_sha4 = executable('test_lighthash_sha4', 'src/tests/test_lighthash_sha4.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_hmac0 = executable('test_lighthash_hmac0', 'src/tests/test_lighthash_hmac0.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_hmac1 = executable('test_lighthash_hmac1', 'src/tests/test_lighthash_hmac1.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_hmac2 = executable('test_lighthash_hmac2', 'src/tests/test_lighthash_hmac2.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_hmac3 = executable('test_lighthash_hmac3', 'src/tests/test_lighthash_hmac3.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test_lighthash_hmac4 = executable('test_lighthash_hmac4', 'src/tests/test_lighthash_hmac4.c',
  link_with: [liblighthash],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test('crypto', test_lightcrypto)
test('crypto cli', test_lightcrypto_cli)
test('ciphers', test_lightciphers)
test('keys', test_lightkeys)
test('hash3', test_lighthash3)
test('hash_sha0', test_lighthash_sha0)
test('hash_sha1', test_lighthash_sha1)
test('hash_sha2', test_lighthash_sha2)
test('hash_sha3', test_lighthash_sha3)
test('hash_sha4', test_lighthash_sha4)
test('hash_hmac0', test_lighthash_hmac0)
test('hash_hmac1', test_lighthash_hmac1)
test('hash_hmac2', test_lighthash_hmac2)
test('hash_hmac3', test_lighthash_hmac3)
test('hash_hmac4', test_lighthash_hmac4)
