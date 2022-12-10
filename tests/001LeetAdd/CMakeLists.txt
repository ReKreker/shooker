set(CMAKE_C_FLAGS "-fPIC")
add_library(victum SHARED victum.c)

add_executable(check check.c)
target_link_libraries(check victum)
