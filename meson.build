project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3'])

liblightssl = static_library('lightssl', 'src/lightssl.c')
liblighthash = static_library('lighthash', 'src/lighthash.c')
test_lightssl = executable('test_lightssl', 'src/test_lightssl.c', link_with: [liblightssl, liblighthash], install : true)

test('basic', test_lightssl)
