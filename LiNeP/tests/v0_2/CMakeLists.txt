add_executable(test_v02_envelopes test_v02_envelopes.cpp)
target_link_libraries(test_v02_envelopes PRIVATE
    $<TARGET_OBJECTS:linep_v02_core>
)
target_include_directories(test_v02_envelopes PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

set_target_properties(test_v02_envelopes PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

add_test(NAME test_v02_envelopes COMMAND test_v02_envelopes)
