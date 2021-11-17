project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3'])

liblightdefs = static_library('lightdefs', 'src/defs.c')
liblightssl = static_library('lightssl', 'src/lightssl.c')
liblighthash = static_library('lighthash', 'src/lighthash.c')
test_lightssl = executable('test_lightssl', 'src/test_lightssl.c',
  link_with: [liblightssl, liblighthash, liblightdefs],
  install : true)

test('server', test_lightssl, args: ['server'])
test('client', test_lightssl, args: ['client'])
