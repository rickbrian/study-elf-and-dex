#include <stdio.h>
#include <android/log.h>

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "51asm",__VA_ARGS__);

//普通的单so
int Add(int a, int b){
    LOGD("a = %d b = %d",a,b);
    return a + b;
}
int Sub(int a, int b){
    LOGD("a = %d b = %d",a,b);
    return a - b;
}


//native 层
int Add(void* env, void* thiz, int a, int b){
    LOGD("a = %d b = %d",a,b);
    return a + b;
}
int Sub(void* env, void* thiz,int a, int b){
    LOGD("a = %d b = %d",a,b);
    return a - b;
}