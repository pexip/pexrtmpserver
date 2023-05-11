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

rtmpserver_lib = library('pexrtmpserver',
  rtmpserver_sources,
  c_args : rtmpserver_flags,
  include_directories : [config_h_inc],
  dependencies : [gstreamer_dep, utils_dep],
  install : true,
)

rtmpserver_dep = declare_dependency(
  link_with: rtmpserver_lib,
  dependencies : [gstreamer_dep, utils_dep],
  include_directories : include_directories('.'))

host_system = host_machine.system()
if host_system != 'windows' and not static_build
  rtmpsrv = executable('rtmpsrv', 'main.c',
    dependencies : [rtmpserver_dep, glib_dep],
    install : true)
endif

gir_scanner = find_program('g-ir-scanner', required : false)
if gir_scanner.found() and not meson.is_cross_build() and not static_build
  gnome = import('gnome')
  gnome.generate_gir(rtmpserver_lib,
    sources : ['pexrtmpserver.c', 'pexrtmpserver.h', 'pexrtmpserver-types.h'],
    namespace : 'PexRtmp',
    nsversion : '0.1',
    includes : ['GObject-2.0', 'Gio-2.0', 'Gst-1.0'],
    install : true,
    extra_args : ['--accept-unprefixed', '--warn-all']
  )
endif
