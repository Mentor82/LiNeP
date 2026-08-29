# ── LiNeP V0.2 Tools & Executables ──────────────────────────────────────────

function(linep_v02_tool TARGET_NAME SOURCE_FILE)
    add_executable(${TARGET_NAME} ${SOURCE_FILE})
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src/pal
    )
    target_link_libraries(${TARGET_NAME} PRIVATE
        $<TARGET_OBJECTS:linep_v02_core>
        $<TARGET_OBJECTS:linep_pal>
    )
    if(WIN32)
        target_link_libraries(${TARGET_NAME} PRIVATE ws2_32)
    endif()
    set_target_properties(${TARGET_NAME} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )
endfunction()

# 1. Standalone CLI Conformance Runner
linep_v02_tool(linep-v02-conformance linep_conformance/main.cpp)

# 2. Deterministic Mock Runtime Server
linep_v02_tool(linep-v02-mock-runtime mock_runtime/main.cpp)

# 3. Cross-Language Golden Frames Generator & Verifier
linep_v02_tool(linep-v02-golden-frames golden_frames_tool.cpp)

# 4. Interactive Live Socket Streaming Test Client
linep_v02_tool(linep-v02-golden-socket-test golden_socket_test.cpp)

# 5. Interactive Live UDP Control Plane Handshake Client
linep_v02_tool(linep-v02-golden-udp-socket-test golden_udp_socket_test.cpp)
