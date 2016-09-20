cmake_minimum_required(VERSION 3.2)

project(lpass)

find_package(libXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

file(GLOB PROJECT_HEADERS *.h)
file(GLOB PROJECT_SOURCES *.c)

add_executable(lpass ${PROJECT_HEADERS} ${PROJECT_SOURCES})
set_target_properties(lpass PROPERTIES
  C_STANDARD 99
  COMPILE_FLAGS "-pedantic -Wall -Wextra -Wno-language-extension-token"
  COMPILE_DEFINITIONS "_GNU_SOURCE"
)
target_link_libraries(lpass ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})

add_custom_target(predoc a2x --no-xmllint -f manpage ${CMAKE_SOURCE_DIR}/lpass.1.txt)
add_custom_target(doc asciidoc -b html5 -a data-uri -a icons -a toc2 -o lpass.1.html ${CMAKE_SOURCE_DIR}/lpass.1.txt DEPENDS predoc)
