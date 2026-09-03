add_executable(test_sl_v02_security_contract
    test_security_contract.cpp
)

target_link_libraries(test_sl_v02_security_contract PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_security_contract PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

add_test(NAME test_sl_v02_security_contract COMMAND test_sl_v02_security_contract)
