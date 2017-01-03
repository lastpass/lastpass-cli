execute_process(COMMAND install -v -d $ENV{DESTDIR}${MANDIR}/man1)
execute_process(COMMAND install -m 0644 -v ${CMAKE_BINARY_DIR}/lpass.1 $ENV{DESTDIR}${MANDIR}/man1/lpass.1)
