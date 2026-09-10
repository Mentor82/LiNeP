add_library(linep_sl_v02 STATIC
    authenticator.cpp
    group_security.cpp
    negotiation.cpp
    plane_authenticator.cpp
    replay_window.cpp
    security_contract.cpp
    session.cpp
    ${PROJECT_SOURCE_DIR}/../LiNeP/src/v0_2/control_plane.cpp
)

target_link_libraries(linep_sl_v02 PUBLIC linep_sl_core)

target_include_directories(linep_sl_v02 PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/../LiNeP/include>
)

set_target_properties(linep_sl_v02 PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)
