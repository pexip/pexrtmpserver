install_headers('rtmpserver.h', subdir : 'rtmpserver')

rtmpserver_sources = [
  'amf.c',
  'client.c',
  'connections.c',
  'handshake.c',
  'utils.c',
  'rtmpserver.c'
]

rtmpserver_lib = shared_library('pexrtmpserver',
  rtmpserver_sources,
  dependencies : [gstreamer_dep, openssl_dep],
  install : true,
)

rtmpserver_dep = declare_dependency(link_with: rtmpserver_lib)
rtmpsrv = executable('rtmpsrv', 'main.c', dependencies : [rtmpserver_dep, gstreamer_dep])

gir_scanner = find_program('g-ir-scanner', required : false)
if gir_scanner.found()
  gnome = import('gnome')
  gnome.generate_gir(rtmpserver_lib,
    sources : ['rtmpserver.c', 'rtmpserver.h'],
    namespace : 'PexRtmp',
    nsversion : '0.1',
    includes : ['GObject-2.0', 'Gio-2.0', 'Gst-1.0'],
    install : true,
    extra_args : ['--accept-unprefixed', '--warn-all']
  )
endif