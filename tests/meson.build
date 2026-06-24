# Security regression tests. These are in-tree tests that use internal
# PexRTMPServer headers/APIs and are built as part of the test suite.

security_test = executable('security_test',
  'security.c',
  c_args : rtmpserver_flags,
  include_directories : [config_h_inc, include_directories('../src')],
  dependencies : [rtmpserver_dep, glib_dep],
)

test('security', security_test)
