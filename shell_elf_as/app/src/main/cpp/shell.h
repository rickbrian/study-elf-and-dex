//
// Created by PC on 2024/3/15.
//

#ifndef SHELL_ELF_SHELL_H
#define SHELL_ELF_SHELL_H

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


#include <android/log.h>
#define MY_DEBUG

#ifdef MY_DEBUG
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "51asm",__VA_ARGS__);
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "51asm",__VA_ARGS__);
#else
#define LOGD(...)
#endif

void* load_elf(const char* sz);
void* myDlsym(void* pBase , const char* szName);

#endif //SHELL_ELF_SHELL_H
