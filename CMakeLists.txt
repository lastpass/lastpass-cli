set(CMAKE_LEGACY_CYGWIN_WIN32 0) # Remove when CMake > 2.8.4 is required
cmake_minimum_required(VERSION 2.8)

project(lpass)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

# pkg_get_variable is not available until CMake >= 3.4.0
# Debian stable still packages CMake 3.0.2
function(pkg_check_variable _pkg _name)
  string(TOUPPER ${_pkg} _pkg_upper)
  string(TOUPPER ${_name} _name_upper)
  string(REPLACE "-" "_" _pkg_upper ${_pkg_upper})
  string(REPLACE "-" "_" _name_upper ${_name_upper})
  set(_output_name "${_pkg_upper}_${_name_upper}")

  execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} --variable=${_name} ${_pkg}
                  OUTPUT_VARIABLE _pkg_result
                  OUTPUT_STRIP_TRAILING_WHITESPACE)

  set("${_output_name}" "${_pkg_result}" CACHE STRING "pkg-config variable ${_name} of ${_pkg}")
endfunction()

if((APPLE) AND (NOT DEFINED OPENSSL_ROOT_DIR))
  set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
endif()

find_package(LibXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

pkg_check_variable(bash-completion completionsdir)

set(PROJECT_NAME lpass)

file(GLOB PROJECT_HEADERS *.h)
file(GLOB PROJECT_SOURCES *.c)

set(PROJECT_DEFINITIONS "_GNU_SOURCE")

set(PROJECT_FLAGS "-std=gnu99 -pedantic -Wall -Wextra -Wno-language-extension-token")
if(APPLE)
  set(PROJECT_FLAGS "${PROJECT_FLAGS} -Wno-deprecated-declarations")
endif()

# Main lpass executable
add_executable(${PROJECT_NAME} ${PROJECT_HEADERS} ${PROJECT_SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES
  C_STANDARD 99
  COMPILE_FLAGS ${PROJECT_FLAGS}
  COMPILE_DEFINITIONS ${PROJECT_DEFINITIONS}
)

target_link_libraries(${PROJECT_NAME} ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})
if (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
  target_link_libraries(${PROJECT_NAME} "-lkvm")
endif (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")

add_custom_command(OUTPUT lpass.1 DEPENDS ${CMAKE_SOURCE_DIR}/lpass.1.txt
        COMMAND a2x -D ./ --no-xmllint -f manpage ${CMAKE_SOURCE_DIR}/lpass.1.txt)
add_custom_command(OUTPUT lpass.1.html DEPENDS ${CMAKE_SOURCE_DIR}/lpass.1.txt
        COMMAND asciidoc -b html5 -a data-uri -a icons -a toc2 -o lpass.1.html ${CMAKE_SOURCE_DIR}/lpass.1.txt)

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
if(BASH_COMPLETION_COMPLETIONSDIR)
install(FILES contrib/lpass_bash_completion DESTINATION ${BASH_COMPLETION_COMPLETIONSDIR} RENAME lpass)
endif()

# Test lpass executable with mock server, link against test versions first
file(GLOB LPTEST_SOURCES test/*.c *.c)
add_executable(lpass-test EXCLUDE_FROM_ALL ${PROJECT_HEADERS} ${LPTEST_SOURCES})
set_target_properties(lpass-test PROPERTIES
  C_STANDARD 99
  COMPILE_FLAGS "${PROJECT_FLAGS} -DTEST_BUILD"
  COMPILE_DEFINITIONS ${PROJECT_DEFINITIONS}
)
target_link_libraries(lpass-test ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})
if (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
  target_link_libraries(lpass-test "-lkvm")
endif (CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
enable_testing()
add_test(test_login ${CMAKE_SOURCE_DIR}/test/tests test_login)
add_test(test_login_wrong_pw_should_fail ${CMAKE_SOURCE_DIR}/test/tests test_login_wrong_pw_should_fail)
add_test(test_add_account ${CMAKE_SOURCE_DIR}/test/tests test_add_account)
add_test(test_add_note ${CMAKE_SOURCE_DIR}/test/tests test_add_note)
add_test(test_add_note_with_field ${CMAKE_SOURCE_DIR}/test/tests test_add_note_with_field)
add_test(test_add_site_note ${CMAKE_SOURCE_DIR}/test/tests test_add_site_note)
add_test(test_add_ssn_name ${CMAKE_SOURCE_DIR}/test/tests test_add_ssn_name)
add_test(test_add_ssh_key ${CMAKE_SOURCE_DIR}/test/tests test_add_ssh_key)
add_test(test_edit_ssh_key ${CMAKE_SOURCE_DIR}/test/tests test_edit_ssh_key)
add_test(test_edit_username ${CMAKE_SOURCE_DIR}/test/tests test_edit_username)
add_test(test_edit_field ${CMAKE_SOURCE_DIR}/test/tests test_edit_field)
add_test(test_edit_reprompt ${CMAKE_SOURCE_DIR}/test/tests test_edit_reprompt)
add_test(test_duplicate ${CMAKE_SOURCE_DIR}/test/tests test_duplicate)
add_test(test_generate ${CMAKE_SOURCE_DIR}/test/tests test_generate)
add_test(test_show ${CMAKE_SOURCE_DIR}/test/tests test_show)
add_test(test_show_json ${CMAKE_SOURCE_DIR}/test/tests test_show_json)
add_test(test_show_note ${CMAKE_SOURCE_DIR}/test/tests test_show_note)
add_test(test_show_reprompt ${CMAKE_SOURCE_DIR}/test/tests test_show_reprompt)
add_test(test_ls ${CMAKE_SOURCE_DIR}/test/tests test_ls)
add_test(test_export ${CMAKE_SOURCE_DIR}/test/tests test_export)
add_test(test_export_extended ${CMAKE_SOURCE_DIR}/test/tests test_export_extended)

add_custom_target(doc-man DEPENDS lpass.1)
add_custom_target(doc-html DEPENDS lpass.1.html)
# See https://cmake.org/pipermail/cmake/2009-January/026520.html
add_custom_target(install-doc COMMAND ${CMAKE_COMMAND} -DMANDIR=${CMAKE_INSTALL_FULL_MANDIR} -P ${CMAKE_SOURCE_DIR}/cmake_extras/install_doc.cmake DEPENDS doc-man)
add_custom_target(uninstall COMMAND ${CMAKE_COMMAND} -DPROJECT_NAME=${PROJECT_NAME} -DMANDIR=${CMAKE_INSTALL_FULL_MANDIR} -P ${CMAKE_SOURCE_DIR}/cmake_extras/uninstall.cmake)
