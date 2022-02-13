cmake_minimum_required(VERSION 3.0)
project(
  vfflib
  VERSION 1.0
  LANGUAGES C
)

add_library(vfflib lib/volume.c lib/fat.c)
target_include_directories(vfflib
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Demo application
add_executable(vfftool tool/vfftool.c)
target_link_libraries(vfftool vfflib)

# Error about any warning whatosever.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
