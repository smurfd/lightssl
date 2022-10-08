project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3'])

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : true)

liblightbig = static_library('lightbig', 'src/lightbig/src/lightbig.c')
liblightssl = static_library('lightssl', 'src/lightssl.c', link_args: '-pthread')
liblightdefs = static_library('lightdefs', 'src/lightdefs.c')
liblighthash = static_library('lighthash', 'src/lighthash.c')
liblightvsh = static_library('lightvsh', 'src/lightvsh.c')
test_lightssl = executable('test_lightssl', 'src/test_lightssl.c',
  link_with: [liblightssl, liblightdefs, liblightbig, liblighthash, liblightvsh],
  link_args: '-pthread',
  dependencies: m_dep,
  install: true)

test('server', test_lightssl, args: ['server'])
test('client', test_lightssl, args: ['client'])
test('big', test_lightssl, args: ['big'])
test('hash', test_lightssl, args: ['hash'])
test('vsh_cli', test_lightssl, args: ['vsh_cli'])
