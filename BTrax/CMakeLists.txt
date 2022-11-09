cmake_minimum_required (VERSION 3.6)

project (H2OLAT)

if (WIN32)
else ()
	set (CMAKE_CXX_FLAGS "-g -O0")
	set (CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}")
	set (WXWIDGETS_VERSION "3.0.1")
endif ()

#add_definitions(-D_WXWIDGETS_3_0_2)

set (H2OLAT_SRC
    bt_coverage/bt_coverage.c
    bt_coverage/bt_hconv.c
    bt_execpath/bt_execpath.c
    bt_execpath/chk_repeat.c
    common/avltree.c
    common/bt_ar_parse.c
    common/bt_utils.c
    common/getopt.c
    dispdb.cpp
    stdafx.cpp
)

#link_directories(${PROJECT_SOURCE_DIR}/../libisdbg)

include_directories (bt_coverage)
include_directories (bt_execpath)
include_directories (common)
include_directories (include)
include_directories (include/btrax)
include_directories (include/DiaSdk)

add_executable (H2OLAT ${H2OLAT_SRC})
#target_link_libraries(H2OLAT pthread)

set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT H2OLAT)