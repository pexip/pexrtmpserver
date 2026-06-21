# The rtmp test-suite. These sources are kept in sync with the copy that lives
# in the (private) pexip/media repository. A few small dependencies on
# media-only helpers are satisfied by the compatibility shims in tests/shims so
# that the exact same sources build and run against a plain upstream GStreamer.

test_includes = include_directories(
  '.',          # rtmpharness.h, handshake_packet.h, wowza_connect.h
  'shims',      # pextest.h, gstharness.h, rtmpserver.h, pex/tools/pextools.h
  '..',         # config.h, utils/*.h
  '../src',     # rtmp.h, handshake.h, client.h
)

test_c_args = [
  '-DTESTS_SRCDIR="@0@"'.format(meson.current_source_dir()),
]

# Test-support GStreamer plugin: upstream-backed replacements for the Pexip
# media elements the shared test-suite expects (pexrtmpsrc/sink, pexcision*,
# codec wrappers). See tests/elements/.
pextestelements_plugin = shared_module('gstpextestelements',
  [
    'elements/gstpextestelements.c',
    'elements/gstpexrtmpbins.c',
    'elements/gstpexcision.c',
  ],
  c_args : rtmpserver_flags,
  include_directories : test_includes,
  dependencies : [rtmpserver_dep, gst_full_dep, gstvideo_dep],
  install : false,
)

rtmp_test_deps = [
  rtmpserver_dep,
  utils_dep,
  gst_full_dep,
  gstcheck_dep,
  gstvideo_dep,
  openssl_dep,
  glib_dep,
]

rtmp_test = executable('rtmp_test',
  ['rtmp.c', 'rtmpharness.c'],
  c_args : rtmpserver_flags + test_c_args,
  include_directories : test_includes,
  dependencies : rtmp_test_deps,
  install : false,
)

# Make the in-tree GStreamer plugins discoverable: the rtmpserver elements
# (build/plugins) and our test-support elements (build/tests).
test_env = environment()
test_env.set('GST_PLUGIN_PATH_1_0',
  meson.current_build_dir() + ':' + meson.current_build_dir() / '..' / 'plugins')
test_env.set('PEX_TESTFILE_PATH', meson.current_source_dir())
test_env.set('CK_DEFAULT_TIMEOUT', '60')

test('rtmp', rtmp_test,
  env : test_env,
  depends : pextestelements_plugin,
  timeout : 600,
)
