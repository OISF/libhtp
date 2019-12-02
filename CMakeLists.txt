cmake_minimum_required(VERSION 2.6)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

set(INCLUDES ${INCLUDES} ${PROJECT_SOURCE_DIR})

add_subdirectory(htp)
add_subdirectory(test/fuzz)
