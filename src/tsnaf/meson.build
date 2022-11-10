libtsnaf_sources = files('''
    context.c
    event.c
    local.c

    npcf-build.c
    npcf-handler.c

    sbi-path.c
    tsnaf-sm.c

    init.c
'''.split())

libulfius_dep = dependency('libulfius')

libtsnaf = static_library('tsnaf',
    sources : libtsnaf_sources,
    dependencies : [libapp_dep,
                    libcrypt_dep,
                    libsbi_dep],
    install : false)

libtsnaf_dep = declare_dependency(
    link_with : libtsnaf,
    dependencies : [libapp_dep,
                    libcrypt_dep,
                    libsbi_dep,
                    libulfius_dep])

tsnaf_sources = files('''
    app.c
    ../main.c
'''.split())

executable('open5gs-tsnafd',
    sources : tsnaf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/tsnaf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : libtsnaf_dep,
    install_rpath : libdir,
    install : true)

