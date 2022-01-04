project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3'])

gmp_dep = dependency('gmp', version : '>=6.2.0')
incdir = include_directories('/opt/homebrew/Cellar/gmp/6.2.1_1/include')

liblightbig = static_library('lightbig', 'src/lightbig.c')
liblightssl = static_library('lightssl', 'src/lightssl.c')
liblightdefs = static_library('lightdefs', 'src/lightdefs.c')
liblighthash = static_library('lighthash', 'src/lighthash.c')
liblightcrypt = static_library('lightcrypt', 'src/lightcrypt.c', include_directories : incdir)
test_lightssl = executable('test_lightssl', 'src/test_lightssl.c',
  link_with: [liblightssl, liblighthash, liblightdefs, liblightcrypt, liblightbig],
  dependencies: [gmp_dep],
  include_directories : incdir,
  install: true)

test('server', test_lightssl, args: ['server'])
test('client', test_lightssl, args: ['client'])
test('big', test_lightssl, args: ['big'])
test('crypt', test_lightssl, args: ['crypt'])
