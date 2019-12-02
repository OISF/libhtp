include_directories(${INCLUDES})

AUX_SOURCE_DIRECTORY(. SOURCES) 

add_library(htplzma ${SOURCES})
