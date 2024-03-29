#ifndef LOAD_ELF_LOAD_ELF_H
#define LOAD_ELF_LOAD_ELF_H

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <linux/elf.h>
#include <elf.h>
#include <memory.h>
#include <sys/mman.h>
#include <string>
#include <vector>
#include <unistd.h>
using namespace  std;



void* load_elf(const char* sz);


#endif //LOAD_ELF_LOAD_ELF_H
