add_library(linep_v02_core OBJECT
    envelopes.cpp
    session.cpp
)

target_include_directories(linep_v02_core PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

set_target_properties(linep_v02_core PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)
