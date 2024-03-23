#include <stdio.h>
#include <dlfcn.h>



#include <android/log.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "51asm",__VA_ARGS__);

__attribute__((constructor)) void MyLoad1(){
    LOGD("void MyLoad1()");

}

