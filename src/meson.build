install_headers(
  ['pexrtmpserver.h', 'pexrtmpserver-types.h'],
  subdir : 'pexrtmpserver')

rtmpserver_sources = [
  'auth.c',
  'client.c',
  'connections.c',
  'handshake.c',
  'pexrtmpserver.c'
]

rtmpserver_lib = shared_library('pexrtmpserver',
  rtmpserver_sources,
  c_args : rtmpserver_flags,
  include_directories : [config_h_inc],
  dependencies : [gstreamer_dep, utils_dep],
  install : true,
)

rtmpserver_dep = declare_dependency(
  link_with: rtmpserver_lib,
  include_directories : include_directories('.'))

rtmpsrv = executable('rtmpsrv', 'main.c',
  dependencies : [rtmpserver_dep, gstreamer_dep],
  install : true)

gir_scanner = find_program('g-ir-scanner', required : false)
if gir_scanner.found()
  gnome = import('gnome')
  gnome.generate_gir(rtmpserver_lib,
    sources : ['pexrtmpserver.c', 'pexrtmpserver.h'],
    namespace : 'PexRtmp',
    nsversion : '0.1',
    includes : ['GObject-2.0', 'Gio-2.0', 'Gst-1.0'],
    install : true,
    extra_args : ['--accept-unprefixed', '--warn-all']
  )
endif
