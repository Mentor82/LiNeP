function(linep_v02_add_test name src)
    add_executable(${name} ${src})
    target_link_libraries(${name} PRIVATE
        $<TARGET_OBJECTS:linep_v02_core>
    )
    target_include_directories(${name} PRIVATE
        ${PROJECT_SOURCE_DIR}/include
    )
    set_target_properties(${name} PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED ON
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

linep_v02_add_test(test_v02_envelopes test_v02_envelopes.cpp)
linep_v02_add_test(test_v02_session   test_v02_session.cpp)
