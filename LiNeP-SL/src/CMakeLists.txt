add_library(linep_sl_core STATIC
    sha256.cpp
    sl1.cpp
    sl2.cpp
)
target_include_directories(linep_sl_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../LiNeP/include>
)

add_library(liblinep_sl SHARED
    cabi_sl.cpp
)
target_link_libraries(liblinep_sl PRIVATE linep_sl_core)
target_compile_definitions(liblinep_sl PRIVATE LINEP_SL_BUILDING_DLL)
target_include_directories(liblinep_sl PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../LiNeP/include>
)
set_target_properties(liblinep_sl PROPERTIES PREFIX "")
