project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3'])

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : true)

liblightbig = static_library('lightbig', 'src/lightbig/src/lightbig.c')
liblightssl = static_library('lightssl', 'src/lightssl.c', link_args: '-pthread')
liblightdefs = static_library('lightdefs', 'src/lightdefs.c')
liblighthash0 = static_library('lighthash0', 'src/lighthash0.c')
libvsh = static_library('vsh', 'src/vsh/vsh.c', dependencies: m_dep)
test_lightssl = executable('test_lightssl', 'src/test_lightssl.c',
  link_with: [liblightssl, liblightdefs, liblightbig, libvsh, liblighthash0],
  link_args: '-pthread',
  dependencies: m_dep,
  install: true)

test('server', test_lightssl, args: ['server'])
test('client', test_lightssl, args: ['client'])
test('big', test_lightssl, args: ['big'])
test('hash0', test_lightssl, args: ['hash0'])
test('vsh', test_lightssl, args: ['vsh'])
