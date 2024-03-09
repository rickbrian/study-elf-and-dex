cmake_minimum_required(VERSION 3.27)
project(DexParse C)

set(CMAKE_C_STANDARD 11)

add_executable(DexParse main.c
        dexFile.h
)
