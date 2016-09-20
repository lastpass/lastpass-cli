find_package(libXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIRS})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

file(GLOB_RECURSE PROJECT_HEADERS *.h)
file(GLOB_RECURSE PROJECT_SOURCES *.c)

include_directories(include)
add_library(lastpass STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})
set_target_properties(lastpass PROPERTIES
  C_STANDARD 99
  COMPILE_FLAGS "-pedantic -Wall -Wextra -Wno-language-extension-token"
  COMPILE_DEFINITIONS "_GNU_SOURCE"
)
target_link_libraries(lastpass ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})
