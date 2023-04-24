project('pexrtmpserver', 'c',
    version : '1.0',
    meson_version : '>= 0.46.0',
    default_options: 'c_std=gnu99')

cc = meson.get_compiler('c')
version = meson.project_version()
gst_req = '>= 1.0.0'
glib_req = '>= 2.40.0'

glib_dep = dependency('glib-2.0', version : glib_req)
static_build = get_option('default_library') == 'static'
if static_build
  gstreamer_dep = dependency('gstreamer-full-1.0', version : gst_req)
else
  gstreamer_dep = dependency('gstreamer-1.0', version : gst_req)
endif
gst_base_dep = dependency('gstreamer-base-1.0', version : gst_req)

openssl_dep = dependency('openssl', version : '>= 1.0.1', required : false)
if not openssl_dep.found()
  libeay32_dep = cc.find_library('libeay32', required : false)
  ssleay32_dep = cc.find_library('ssleay32', required : false)
  if libeay32_dep.found() and ssleay32_dep.found()
    openssl_dep = declare_dependency (dependencies : [libeay32_dep, ssleay32_dep])
  endif
endif

winsock2_dep = cc.find_library('ws2_32', required : false)

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

install_dir = get_option('libdir')
plugins_install_dir = '@0@/gstreamer-1.0'.format(install_dir)

rtmpserver_flags = ['-DPEX_RTMPSERVER_EXPORTS']
if static_build
  rtmpserver_flags += ['-DPEX_RTMPSERVER_STATIC_BUILD']
endif

# config.h generation
config_h_inc = include_directories('.')
core_conf = configuration_data()
core_conf.set('PACKAGE', '"Pexip RTMP Server"')
core_conf.set('PACKAGE_VERSION', '"@0@"'.format(version))
core_conf.set('VERSION', '"@0@"'.format(version))
core_conf.set('PLUGIN_DIR', '"@0@"'.format(join_paths(get_option('prefix'), plugins_install_dir)))

check_headers = [
  'linux/sockios.h',
]
foreach h : check_headers
  # Only define if header exist so that both #if and #ifdef works
  if cc.has_header(h)
    define = 'HAVE_' + h.underscorify().to_upper()
    core_conf.set10(define, 1)
  endif
endforeach

if openssl_dep.found()
  core_conf.set10('HAVE_OPENSSL', openssl_dep.found())
endif

configure_file(output : 'config.h', input: 'config.h.meson',
    configuration : core_conf)

subdir('pkgconfig')
subdir('utils')
subdir('src')
subdir('plugins')
