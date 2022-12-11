set(CMAKE_C_FLAGS "-fPIC")
add_library(001Lib SHARED victum.c)

add_executable(001Bin check.c)
target_link_libraries(001Bin 001Lib)
