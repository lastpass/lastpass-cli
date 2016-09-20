file(GLOB PROJECT_HEADERS *.h)
file(GLOB PROJECT_SOURCES *.c)

include_directories(${CMAKE_SOURCE_DIR}/lib/include)
add_executable(lpass ${PROJECT_HEADERS} ${PROJECT_SOURCES})
set_target_properties(lpass PROPERTIES
  C_STANDARD 99
  COMPILE_FLAGS "-pedantic -Wall -Wextra -Wno-language-extension-token"
  COMPILE_DEFINITIONS "_GNU_SOURCE"
)
target_link_libraries(lpass lastpass)
