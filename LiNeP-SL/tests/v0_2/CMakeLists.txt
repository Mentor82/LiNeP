add_executable(test_sl_v02_security_contract
    test_security_contract.cpp
)

target_link_libraries(test_sl_v02_security_contract PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_security_contract PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)

add_test(NAME test_sl_v02_security_contract COMMAND test_sl_v02_security_contract)

add_executable(test_sl_v02_negotiation
    test_negotiation.cpp
)
target_link_libraries(test_sl_v02_negotiation PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_negotiation PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME test_sl_v02_negotiation COMMAND test_sl_v02_negotiation)

add_executable(test_sl_v02_session
    test_session.cpp
)
target_link_libraries(test_sl_v02_session PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_session PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME test_sl_v02_session COMMAND test_sl_v02_session)

add_executable(test_sl_v02_replay_window
    test_replay_window.cpp
)
target_link_libraries(test_sl_v02_replay_window PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_replay_window PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME test_sl_v02_replay_window COMMAND test_sl_v02_replay_window)

add_executable(test_sl_v02_authenticators
    test_authenticators.cpp
)
target_link_libraries(test_sl_v02_authenticators PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_authenticators PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME test_sl_v02_authenticators COMMAND test_sl_v02_authenticators)

add_executable(test_sl_v02_plane_protection
    test_plane_protection.cpp
)
target_link_libraries(test_sl_v02_plane_protection PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_plane_protection PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME test_sl_v02_plane_protection COMMAND test_sl_v02_plane_protection)

add_executable(test_sl_v02_group_security
    test_group_security.cpp
)
target_link_libraries(test_sl_v02_group_security PRIVATE linep_sl_v02)
set_target_properties(test_sl_v02_group_security PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
add_test(NAME test_sl_v02_group_security COMMAND test_sl_v02_group_security)


