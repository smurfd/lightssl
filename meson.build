project('lightssl', 'c', version : '0.1', default_options : ['warning_level=3', 'c_std=c99'])

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

liblightssl = static_library('lightssl', 'src/lightssl.c', link_args: '-pthread')
liblightdefs = static_library('lightdefs', 'src/lightdefs.c')
liblighthash = static_library('lighthash', 'src/lighthash.c')
liblighthash3 = static_library('lighthash3', 'src/lighthash3.c')
liblightvsh = static_library('lightvsh', 'src/lightvsh.c',
  link_args: '-pthread',
  dependencies: [m_dep, p_dep],
  c_args: build_args)

test_lightssl = executable('test_lightssl', 'src/test_lightssl.c',
  link_with: [liblightssl, liblightdefs, liblighthash, liblighthash3, liblightvsh],
  link_args: '-pthread',
  c_args: build_args,
  dependencies: [m_dep, p_dep],
  install: true)

test('server', test_lightssl, args: ['server'])
test('client', test_lightssl, args: ['client'])
test('hash', test_lightssl, args: ['hash'])
test('hash3', test_lightssl, args: ['hash3'])
test('vsh_cli', test_lightssl, args: ['vsh_cli'])