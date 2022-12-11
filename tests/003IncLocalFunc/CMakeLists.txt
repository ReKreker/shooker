set(CMAKE_C_FLAGS "-fPIC")
add_library(003Lib SHARED victum.c)

add_executable(003Bin check.c)
target_link_libraries(003Bin 003Lib)
