cmake_minimum_required(VERSION 3.20)
project(LiNeP_SL VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTING "Build LiNeP-SL unit tests" ON)
option(LINEP_SL_BUILD_V02 "Build experimental LiNeP-SL V0.2 contract" OFF)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../LiNeP/include
)

add_subdirectory(src)

if(LINEP_SL_BUILD_V02)
    add_subdirectory(src/v0_2)
endif()

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
    if(LINEP_SL_BUILD_V02)
        add_subdirectory(tests/v0_2)
    endif()
endif()
