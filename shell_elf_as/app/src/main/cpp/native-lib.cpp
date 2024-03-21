#include <jni.h>
#include <string>
#include "shell.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_org_shell_1elf_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";

    void* handle = load_elf("/data/local/tmp/libtest.so");

    typedef int (*PFN_ADD)(int,int);


    PFN_ADD pAdd = (PFN_ADD)myDlsym(handle,"Add");
     if (pAdd)
     {
         int n = pAdd(1, 3);
         printf("1 + 3 = %d ",n);
     }

     PFN_ADD pSub=  (PFN_ADD)myDlsym(handle,"Sub");
     if (pSub)
     {
         printf("1 - 3 = %d ",pSub(1,3));
     }


    return env->NewStringUTF(hello.c_str());
}

