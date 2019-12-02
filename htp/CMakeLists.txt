include_directories(${INCLUDES})

add_subdirectory(lzma)

AUX_SOURCE_DIRECTORY(. SOURCES) 

add_library(htp ${SOURCES})
target_link_libraries(htp htplzma)
