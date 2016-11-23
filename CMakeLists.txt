cmake_minimum_required(VERSION 2.8)

project(lpass)

if((APPLE) AND (NOT DEFINED OPENSSL_ROOT_DIR))
  set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl")
endif()

find_package(LibXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

set(PROJECT_NAME lpass)

file(GLOB PROJECT_HEADERS *.h)
file(GLOB PROJECT_SOURCES *.c)

set(PROJECT_DEFINITIONS "_GNU_SOURCE")

set(PROJECT_FLAGS "-pedantic -Wall -Wextra -Wno-language-extension-token")
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

add_custom_target(predoc a2x --no-xmllint -f manpage ${CMAKE_SOURCE_DIR}/lpass.1.txt)
add_custom_target(doc asciidoc -b html5 -a data-uri -a icons -a toc2 -o lpass.1.html ${CMAKE_SOURCE_DIR}/lpass.1.txt DEPENDS predoc)
