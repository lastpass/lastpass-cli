if(APPLE)
  list(INSERT CMAKE_PREFIX_PATH 0 /usr/local)
  list(INSERT CMAKE_LIBRARY_PATH 0 /usr/local)
endif()

# Project dependencies
find_package(LibXml2 REQUIRED)
message(STATUS "Include dir is ${LIBXML2_INCLUDE_DIR}")
if(APPLE)
  set(LIBXML2_INCLUDE_DIR "/usr/local/opt/libxml2/include/libxml2")
  message(STATUS "Include dir changed to ${LIBXML2_INCLUDE_DIR}")
endif()
include_directories(${LIBXML2_INCLUDE_DIR})

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(CURL REQUIRED)
include_directories(${CURL_INCLUDE_DIR})

# Project name
set(PROJECT_NAME lastpass)

# Project files
file(GLOB_RECURSE PROJECT_HEADERS *.h)
file(GLOB_RECURSE PROJECT_SOURCES *.c)

# Project definitions
set(PROJECT_DEFINITIONS "_GNU_SOURCE")

# Project compilation flags
set(PROJECT_FLAGS "-pedantic -Wall -Wextra -Wno-language-extension-token")
if(APPLE)
  set(PROJECT_FLAGS "${PROJECT_FLAGS} -Wno-deprecated-declarations")
endif()

# Project libraries
set(PROJECT_LIBRARIES ${LIBXML2_LIBRARIES} ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})

get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
endforeach()

include_directories(include)
add_library(${PROJECT_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})
set_target_properties(${PROJECT_NAME} PROPERTIES
  C_STANDARD 99
  COMPILE_FLAGS ${PROJECT_FLAGS}
  COMPILE_DEFINITIONS ${PROJECT_DEFINITIONS}
)
target_link_libraries(${PROJECT_NAME} ${PROJECT_LIBRARIES})

# Project install headers
install(FILES ${PROJECT_HEADERS} DESTINATION include/lastpass)

# Project install lib
install(TARGETS lastpass ARCHIVE DESTINATION lib)
