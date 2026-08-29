function(linep_v02_add_test name src)
    add_executable(${name} ${src})
    target_link_libraries(${name} PRIVATE
        $<TARGET_OBJECTS:linep_v02_core>
        $<TARGET_OBJECTS:linep_pal>
    )
    target_include_directories(${name} PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/src/pal
    )
    if(WIN32)
        target_link_libraries(${name} PRIVATE ws2_32)
    endif()
    set_target_properties(${name} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

linep_v02_add_test(test_v02_envelopes                       test_v02_envelopes.cpp)
linep_v02_add_test(test_v02_session                         test_v02_session.cpp)
linep_v02_add_test(test_v02_socket_multiplexing             test_v02_socket_multiplexing.cpp)
linep_v02_add_test(test_v02_lifecycle_cancel_backpressure   test_v02_lifecycle_cancel_backpressure.cpp)
linep_v02_add_test(test_v02_conformance                    test_v02_conformance.cpp)
linep_v02_add_test(test_v02_udp_control_plane              test_v02_udp_control_plane.cpp)
linep_v02_add_test(test_v02_golden_interop                 test_v02_golden_interop.cpp)
