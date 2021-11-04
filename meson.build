project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3'])

liblightssl = static_library('lightssl', 'src/lightssl.c')
test_lightssl = executable('test_lightssl', 'src/test_lightssl.c', link_with: liblightssl, install : true)

test('basic', test_lightssl)
