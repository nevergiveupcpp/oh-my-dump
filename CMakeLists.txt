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

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" OMD_TARGET_PROCESSOR)
if (WIN32 AND CMAKE_VS_PLATFORM_NAME)
    string(TOLOWER "${CMAKE_VS_PLATFORM_NAME}" OMD_TARGET_PROCESSOR)
elseif (APPLE AND CMAKE_OSX_ARCHITECTURES)
    string(TOLOWER "${CMAKE_OSX_ARCHITECTURES}" OMD_TARGET_PROCESSOR)
endif ()

if (WIN32 AND OMD_TARGET_PROCESSOR MATCHES "^(amd64|x86_64|x64)$")
    set(IDA_LIBRARY_SUFFIXES x64_win_64 x64_win_vc_64)
    set(IDA_PLATFORM_DEFINITIONS __NT__)
elseif (WIN32 AND OMD_TARGET_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(IDA_LIBRARY_SUFFIXES arm64_win_64)
    set(IDA_PLATFORM_DEFINITIONS __NT__ __ARM__)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND OMD_TARGET_PROCESSOR MATCHES "^(amd64|x86_64|x64)$")
    set(IDA_LIBRARY_SUFFIXES x64_linux_64)
    set(IDA_PLATFORM_DEFINITIONS __LINUX__)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND OMD_TARGET_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(IDA_LIBRARY_SUFFIXES arm64_linux_64)
    set(IDA_PLATFORM_DEFINITIONS __LINUX__ __ARM__)
elseif (APPLE AND OMD_TARGET_PROCESSOR MATCHES "^(amd64|x86_64|x64)$")
    set(IDA_LIBRARY_SUFFIXES x64_mac_64)
    set(IDA_PLATFORM_DEFINITIONS __MAC__)
elseif (APPLE AND OMD_TARGET_PROCESSOR MATCHES "^(aarch64|arm64)$")
    set(IDA_LIBRARY_SUFFIXES arm64_mac_64)
    set(IDA_PLATFORM_DEFINITIONS __MAC__ __ARM__)
else ()
    message(FATAL_ERROR "Unsupported target: ${CMAKE_SYSTEM_NAME}/${OMD_TARGET_PROCESSOR}")
endif ()

find_library(IDA_LIBRARY
        NAMES ida ida.lib "${IDA_LIBRARY_NAME}"
        PATHS "${IDA_SDK_DIR}/src/lib"
        PATH_SUFFIXES ${IDA_LIBRARY_SUFFIXES}
        NO_DEFAULT_PATH
)

if (NOT IDA_LIBRARY)
    message(FATAL_ERROR "IDA library not found under ${IDA_SDK_DIR}/src/lib (expected ${IDA_LIBRARY_SUFFIXES}).")
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
        SKIP_BUILD_RPATH TRUE
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
        ${IDA_PLATFORM_DEFINITIONS}
        __IDP__
        __EA64__
        $<$<CXX_COMPILER_ID:MSVC>:_SILENCE_CXX20_IS_POD_DEPRECATION_WARNING>
        dont_use_snprintf=snprintf
        dont_use_fgetc=fgetc
        _strtoui64=strtoull
)

install(FILES "$<TARGET_FILE:oh-my-dump>" DESTINATION .)
