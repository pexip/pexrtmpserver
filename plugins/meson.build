rtmp_sources = [
  'pexrtmpplugins.c',
  'pexrtmpserversink.c',
  'pexrtmpserversrc.c',
]

rtmpplugins = library('gstrtmpserverelements',
  rtmp_sources,
  include_directories : [config_h_inc],
  dependencies : [rtmpserver_dep, gst_full_dep],
  install : true,
  install_dir : plugins_install_dir,
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(rtmpplugins,
  subdirs : 'pexrtmpserver')
