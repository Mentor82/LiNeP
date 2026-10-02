add_library(linep_sl_v02 STATIC
    authenticator.cpp
    authorization.cpp
    crypto_provider.cpp
    governance.cpp
    group_security.cpp
    negotiation.cpp
    plane_authenticator.cpp
    replay_window.cpp
    security_contract.cpp
    session.cpp
    sl2_handshake.cpp
    ${PROJECT_SOURCE_DIR}/../LiNeP/src/v0_2/control_plane.cpp
    ${PROJECT_SOURCE_DIR}/../LiNeP/src/v0_2/envelopes.cpp
    ${PROJECT_SOURCE_DIR}/../LiNeP/src/v0_2/vision.cpp
    ${PROJECT_SOURCE_DIR}/../LiNeP/src/core/sha256.cpp
    ${PROJECT_SOURCE_DIR}/../LiNeP/src/core/security.cpp
)

target_link_libraries(linep_sl_v02 PUBLIC linep_sl_core OpenSSL::Crypto)

target_include_directories(linep_sl_v02 PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/../LiNeP/include>
)

target_include_directories(linep_sl_v02 PRIVATE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/../LiNeP/src/core>
)

set_target_properties(linep_sl_v02 PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)
