# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.12)
set (CMAKE_CXX_STANDARD 17)

project(SEALNetExamples VERSION 3.4.5 LANGUAGES CXX)

# Executable will be in ../bin
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SEALNetExamples_SOURCE_DIR}/../bin)

include(GNUInstallDirs)

add_executable(sealnetexamples examples.cpp)
target_sources(sealnetexamples
    PRIVATE
    examples.cpp examples.h
)


# Add local include directories for build
set(SEALNetParent_DIR ${SEALNetExamples_SOURCE_DIR}/..)
target_include_directories(sealnetexamples
    PRIVATE $<BUILD_INTERFACE:${SEALNetParent_DIR}>
    PRIVATE /usr/local/include/SEAL-3.4/
    PRIVATE /usr/local/include/   
)

# Link Microsoft SEAL C version
target_link_directories(sealnetexamples PRIVATE /usr/local/lib)
set(SEALNetNative_LIB ${SEALNetExamples_SOURCE_DIR}/../build/libsealnetnative.a)
target_link_libraries(sealnetexamples 
    $<BUILD_INTERFACE:${SEALNetNative_LIB}>
    libseal-3.4.a
    z
)
