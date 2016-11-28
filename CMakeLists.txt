set(CMAKE_LEGACY_CYGWIN_WIN32 0) # Remove when CMake > 2.8.4 is required
cmake_minimum_required(VERSION 2.8)

project(lpass)

include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

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

add_executable(${PROJECT_NAME} ${PROJECT_HEADERS} ${PROJECT_SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES
  C_STANDARD 99
  COMPILE_FLAGS ${PROJECT_FLAGS}
  COMPILE_DEFINITIONS ${PROJECT_DEFINITIONS}
)
target_link_libraries(${PROJECT_NAME} ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)
if(BASH_COMPLETION_COMPLETIONSDIR)
  install(FILES contrib/lpass_bash_completion DESTINATION ${BASH_COMPLETION_COMPLETIONSDIR} RENAME lpass)
endif()

add_custom_target(doc-man a2x --no-xmllint -f manpage ${CMAKE_SOURCE_DIR}/lpass.1.txt)
add_custom_target(doc asciidoc -b html5 -a data-uri -a icons -a toc2 -o lpass.1.html ${CMAKE_SOURCE_DIR}/lpass.1.txt DEPENDS doc-man)
add_custom_target(install-doc install -v -d ${CMAKE_INSTALL_FULL_MANDIR}/man1 && install -m 0644 -v lpass.1 ${CMAKE_INSTALL_FULL_MANDIR}/man1/lpass.1 DEPENDS doc)

