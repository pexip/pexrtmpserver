project('pexrtmpserver', 'c',
    version : '1.0',
    meson_version : '>= 0.46.0',
    default_options: 'c_std=gnu99')

cc = meson.get_compiler('c')
version = meson.project_version()
gst_req = '>= 1.0.0'

gstreamer_dep = dependency('gstreamer-1.0', version : gst_req)
gst_base_dep = dependency('gstreamer-base-1.0', version : gst_req)
openssl_dep = dependency('openssl', version : '>= 1.0.1')

winsock2_dep = cc.find_library('ws2_32', required : false)

add_project_arguments('-DHAVE_CONFIG_H', language: 'c')

install_dir = get_option('libdir')
plugins_install_dir = '@0@/gstreamer-1.0'.format(install_dir)

rtmpserver_flags = ['-DPEX_RTMPSERVER_EXPORTS']

# config.h generation
config_h_inc = include_directories('.')
core_conf = configuration_data()
core_conf.set('PACKAGE', '"Pexip RTMP Server"')
core_conf.set('PACKAGE_VERSION', '"@0@"'.format(version))
core_conf.set('VERSION', '"@0@"'.format(version))
core_conf.set('PLUGIN_DIR', '"@0@"'.format(join_paths(get_option('prefix'), plugins_install_dir)))

check_headers = [
  'string.h',
  'strings.h',
  'unistd.h',
  'stdlib.h',
]
foreach h : check_headers
  # Only define if header exist so that both #if and #ifdef works
  if cc.has_header(h)
    define = 'HAVE_' + h.underscorify().to_upper()
    core_conf.set10(define, 1)
  endif
endforeach
configure_file(output : 'config.h', input: 'config.h.meson',
    configuration : core_conf)

subdir('pkgconfig')
subdir('src')
