cmake_minimum_required(VERSION 3.10)
project(ascii_animation)

# No need to explicitly set compiler paths on Ubuntu as the system defaults will be used
add_executable(animation
    main.c
    animation.c
    screen.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
