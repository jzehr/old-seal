# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.2.0 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)

add_executable(sealexamples examples.cpp)

## this will create a new executable, called 'first argument' in tuple, based off file from second argument in tuple ##
add_executable(temp_blah temp_examples.cpp)
add_executable(CKKS_test CKKS.cpp)
add_executable(sub_test t.cpp)
add_executable(compare_test compare.cpp)
add_executable(pairwise_test pairwise.cpp)
add_executable(matrix_test matrix_test.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Link Microsoft SEAL
target_link_libraries(sealexamples SEAL::seal)

## link the libraries between your executable and SEAL ##
target_link_libraries(temp_blah SEAL::seal)
target_link_libraries(CKKS_test SEAL::seal)
target_link_libraries(sub_test SEAL::seal)
target_link_libraries(compare_test SEAL::seal)
target_link_libraries(pairwise_test SEAL::seal)
target_link_libraries(matrix_test SEAL::seal)
