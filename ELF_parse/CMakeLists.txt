cmake_minimum_required(VERSION 3.27)
project(ELF_parse)

set(CMAKE_CXX_STANDARD 17)

add_executable(ELF_parse main.cpp
        elf-h.h
        elf-em.h
        ELF.cpp
        ELF.h)
