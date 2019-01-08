rtmp_sources = [
  'pexrtmpplugins.c',
  'pexrtmpserversink.c',
  'pexrtmpserversrc.c',
]

rtmpplugins = library('gstrtmpserverelements',
  rtmp_sources,
  include_directories : [config_h_inc],
  dependencies : [rtmpserver_dep, gst_base_dep],
  install : true,
  install_dir : plugins_install_dir,
)
