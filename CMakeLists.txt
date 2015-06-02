cmake_minimum_required(VERSION 2.8)

project(lastpass-cli)

include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)
include(FindPkgConfig)

CHECK_C_COMPILER_FLAG("-std=gnu99" COMPILER_SUPPORTS_GNU99)

if(COMPILER_SUPPORTS_GNU99)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
endif(COMPILER_SUPPORTS_GNU99)

add_definitions(-D_GNU_SOURCE)

include_directories(${CMAKE_BINARY_DIR})

pkg_search_module(libxml REQUIRED libxml-2.0)

include_directories(${libxml_INCLUDE_DIRS})

add_executable(lpass
  agent.c
  agent.h
  blob.c
  blob.h
  cipher.c
  cipher.h
  clipboard.c
  clipboard.h
  cmd.c
  cmd.h
  cmd-duplicate.c
  cmd-edit.c
  cmd-export.c
  cmd-generate.c
  cmd-login.c
  cmd-logout.c
  cmd-ls.c
  cmd-rm.c
  cmd-show.c
  cmd-sync.c
  config.c
  config.h
  endpoints.c
  endpoints.h
  endpoints-login.c
  http.c
  http.h
  kdf.c
  kdf.h
  list.h
  lpass.c
  password.c
  password.h
  pbkdf2.c
  process.c
  process.h
  session.c
  session.h
  terminal.c
  terminal.h
  upload-queue.c
  upload-queue.h
  util.c
  util.h
  version.h
  xml.c
  xml.h
)

target_link_libraries(lpass crypto)
target_link_libraries(lpass curl)
target_link_libraries(lpass ssl)

target_link_libraries(lpass ${libxml_LIBRARIES})

add_custom_command(
  OUTPUT certificate.h
  COMMAND ${CMAKE_SOURCE_DIR}/gen_certificate.sh ${CMAKE_SOURCE_DIR}/thawte.pem certificate.h
  DEPENDS thawte.pem
)

add_custom_target(certificate
  DEPENDS certificate.h
 )

add_dependencies(lpass certificate)
