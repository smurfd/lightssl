project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3'])

liblightbig = static_library('lightbig', 'src/lightbig/src/lightbig.c')
liblightssl = static_library('lightssl', 'src/lightssl.c', link_args: '-pthread')
liblightdefs = static_library('lightdefs', 'src/lightdefs.c')
liblighthash = static_library('lighthash', 'src/lighthash.c')
libvsh = static_library('vsh', 'src/vsh/vsh.c')
test_lightssl = executable('test_lightssl', 'src/test_lightssl.c',
  link_with: [liblightssl, liblighthash, liblightdefs, liblightbig, libvsh],
  link_args: '-pthread',
  install: true)

test('server', test_lightssl, args: ['server'])
test('client', test_lightssl, args: ['client'])
test('big', test_lightssl, args: ['big'])
test('hash', test_lightssl, args: ['hash'])
test('vsh', test_lightssl, args: ['vsh'])
