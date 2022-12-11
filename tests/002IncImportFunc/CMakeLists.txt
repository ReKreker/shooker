set(CMAKE_C_FLAGS "-fPIC")
add_library(002Lib SHARED victum.c)

add_executable(002Bin check.c)
target_link_libraries(002Bin 002Lib)
