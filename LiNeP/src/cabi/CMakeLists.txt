# C-ABI wrapper — extern "C" flat API for Python/cffi and plain-C callers
add_library(linep_cabi OBJECT
    cabi.cpp
)

target_include_directories(linep_cabi
    PUBLIC  ${PROJECT_SOURCE_DIR}/include
    PRIVATE ${PROJECT_SOURCE_DIR}/src     # allows ../pal/socket.hpp etc.
)

# Depends on framing, tcp, pal — bring in all include paths
target_link_libraries(linep_cabi
    PUBLIC linep_core
    PUBLIC linep_tcp
    PUBLIC linep_pal
)

if(LINEP_BUILD_SHARED)
    target_compile_definitions(linep_cabi PUBLIC LINEP_SHARED LINEP_EXPORTS)
endif()
