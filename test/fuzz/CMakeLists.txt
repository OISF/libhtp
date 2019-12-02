set (INCLUDES ${INCLUDES} ${PROJECT_SOURCE_DIR}/htp ${PROJECT_SOURCE_DIR}/htp/lzma)
include_directories(${INCLUDES})

add_executable (fuzz_htp fuzz_htp.c onefile.c ../test.c)
add_executable (fuzz_htpd fuzz_htp.c onedir.c ../test.c)

target_link_libraries (fuzz_htp htp z)
target_link_libraries (fuzz_htpd htp z)

#add_executable(fuzz_lzma_dec onefile.c fuzz_lzma_dec.c)
#target_link_libraries(fuzz_lzma_dec lzmac)

#add_executable(fuzz_lzma_round onefile.c fuzz_lzma_round.c)
#target_link_libraries(fuzz_lzma_round lzmac)
