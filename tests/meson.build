# Security regression tests. These only depend on glib/gst and the public
# PexRTMPServer library, so they are always built as part of the test suite.

security_test = executable('security_test',
  'security.c',
  c_args : rtmpserver_flags,
  include_directories : [config_h_inc, include_directories('../src')],
  dependencies : [rtmpserver_dep, glib_dep],
)

test('security', security_test)
