cmake_minimum_required(VERSION 3.31)
project(oh-my-dump)

set(CMAKE_CXX_STANDARD 20)

if (NOT EXISTS "${IDA_SDK_DIR}")
    message(FATAL_ERROR "IDA SDK path not found. Set IDA_SDK_DIR to the IDA SDK directory.")
endif ()

set(IDA_INCLUDE_DIR "${IDA_SDK_DIR}/src/include")

if (NOT EXISTS "${IDA_INCLUDE_DIR}/ida.hpp")
    message(FATAL_ERROR "Invalid IDA_SDK_DIR: ${IDA_SDK_DIR}")
endif ()

find_library(IDA_LIBRARY
        NAMES ida ida.lib "${IDA_LIBRARY_NAME}"
        PATHS "${IDA_SDK_DIR}/src/lib"
        PATH_SUFFIXES x64_win_vc_64
        NO_DEFAULT_PATH
)

if (NOT IDA_LIBRARY)
    message(FATAL_ERROR "IDA library not found under ${IDA_SDK_DIR}/src/lib/${IDA_LIB_SUFFIX}")
endif ()

get_filename_component(IDA_LIB_DIR "${IDA_LIBRARY}" DIRECTORY)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
        "idaplugin/*.cpp"
        "idaplugin/*.h"
)

find_package(nlohmann_json CONFIG REQUIRED)

add_library(oh-my-dump SHARED ${SOURCES})

set_target_properties(oh-my-dump
        PROPERTIES
        PREFIX ""
)

target_include_directories(oh-my-dump
        PRIVATE
        "${CMAKE_SOURCE_DIR}/idaplugin"
        "${IDA_INCLUDE_DIR}"
)

target_link_directories(oh-my-dump
        PRIVATE
        "${IDA_LIB_DIR}"
)

target_link_libraries(oh-my-dump
        PRIVATE
        nlohmann_json::nlohmann_json
        "${IDA_LIBRARY}"
)

target_compile_definitions(oh-my-dump PRIVATE
        __NT__
        __IDP__
        __EA64__
        _SILENCE_CXX20_IS_POD_DEPRECATION_WARNING
        dont_use_snprintf=snprintf
        dont_use_fgetc=fgetc
        _strtoui64=strtoull
)
