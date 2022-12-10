project(tests)
cmake_minimum_required(VERSION 3.9)
include(CTest)

if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed.\nUse build/ directory")
endif()

if (NOT DEFINED CC)
    set(CC "/usr/bin/gcc")
elseif (NOT CC MATCHES "gcc")
    message(FATAL_ERROR "Shooker is based on gcc-features so use gcc")
endif()
set(CMAKE_C_COMPILER "${CC}")

if (${CMAKE_SYSTEM_NAME} MATCHES Linux)
    set(TEST_CMD "./test.sh")
else()
    message(FATAL_ERROR "There is no test-sciprt for ${CMAKE_SYSTEM_NAME}") 
endif()

foreach (test 001LeetAdd)
    set(SRC "${CMAKE_SOURCE_DIR}/${test}")
    set(DST "${CMAKE_BINARY_DIR}/${test}")

    add_subdirectory("${test}")

    file(COPY_FILE "${SRC}/hooks.xml" "${DST}/hooks.xml")
    file(COPY_FILE "${CMAKE_SOURCE_DIR}/${TEST_CMD}" "${CMAKE_BINARY_DIR}/${TEST_CMD}")

    add_test(NAME "${test}"
        COMMAND "${TEST_CMD}" "${DST}")
endforeach()
