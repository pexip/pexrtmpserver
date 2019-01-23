utils_headers = [
  'amf.h',
  'gstbufferqueue.h',
  'parse.h',
  'tcp.h',
]

utils_sources = [
  'amf.c',
  'flv.c',
  'gstbufferqueue.c',
  'parse.c',
  'tcp.c',
]

if openssl_dep.found()
  utils_headers += ['ssl.h']
  utils_sources += ['ssl.c']
endif

install_headers(utils_headers, subdir : 'pexrtmpserver/utils')

utils_lib = static_library('rtmpserver-utils',
  utils_sources,
  c_args : rtmpserver_flags,
  dependencies : [gstreamer_dep, openssl_dep, winsock2_dep],
  install : false,
)

utils_dep = declare_dependency(
  link_with: utils_lib,
  dependencies : [openssl_dep, winsock2_dep],
  include_directories : include_directories('..'))
