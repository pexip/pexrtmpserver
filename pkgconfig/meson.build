pkgconf = configuration_data()
pkgconf.set('prefix', join_paths(get_option('prefix')))
pkgconf.set('exec_prefix', '${prefix}')
pkgconf.set('libdir', '${prefix}/@0@'.format(get_option('libdir')))
pkgconf.set('includedir', '${prefix}/@0@'.format(get_option('includedir')))
pkgconf.set('VERSION', meson.project_version())
pkgconf.set('RTMPSERVER_STATIC_BUILD', rtmpserver_static_build)

requires = ''
if cc.get_id() == 'intel' and host_system != 'windows'
  requires = 'openssl'
endif
pkgconf.set('REQUIRES', requires)

configure_file(
    input : 'libpexrtmpserver.pc.in',
    output: 'libpexrtmpserver.pc',
    configuration : pkgconf,
    install_dir : join_paths(get_option('libdir'), 'pkgconfig'))
