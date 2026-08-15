add_library(vikingbio STATIC
    src/vikingbio.c
)

target_include_directories(vikingbio
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(vikingbio PRIVATE -O2 -Wall -Wextra)
