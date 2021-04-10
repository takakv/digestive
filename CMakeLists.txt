cmake_minimum_required(VERSION 3.16)
project(hash_practice C)

set(CMAKE_C_STANDARD 11)

add_executable(hash_practice main.c sha1.c sha1.h types.h)