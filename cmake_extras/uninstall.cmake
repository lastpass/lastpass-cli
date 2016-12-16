################ CMake Uninstall Template #######################
# Used for generating a "make uninstall" target
#################################################################

set(MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/install_manifest.txt")

if(EXISTS ${MANIFEST})
    message(STATUS "============== Uninstalling ${PROJECT_NAME} ===================")

    file(STRINGS ${MANIFEST} files)
    set (files ${files} "${MANDIR}/man1/lpass.1")
    foreach(file ${files})
        set(file "$ENV{DESTDIR}${file}")
        if(EXISTS ${file})
            message(STATUS "Removing file: '${file}'")

            execute_process(
                COMMAND ${CMAKE_COMMAND} -E remove ${file}
                OUTPUT_VARIABLE rm_out
                RESULT_VARIABLE rm_retval
            )

            if( rm_retval )
                message(FATAL_ERROR "Failed to remove file: '${file}'.")
            endif()
        else()
            message(STATUS "File '${file}' does not exist.")
        endif()
    endforeach(file)
else()
    message(STATUS "Cannot find install manifest: '${MANIFEST}'")
    message(STATUS "Have you *actually* run `make install` yet?")
endif()
