add_library(linep_sl_v02 STATIC
    negotiation.cpp
    security_contract.cpp
    session.cpp
)

target_include_directories(linep_sl_v02 PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/../LiNeP/include>
)

set_target_properties(linep_sl_v02 PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)
