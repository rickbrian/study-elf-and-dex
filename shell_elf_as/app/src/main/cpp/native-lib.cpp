#include <jni.h>
#include <string>
#include <dlfcn.h>

typedef int (*PFN_ADD)(int,int);
PFN_ADD pfnAdd = nullptr;
PFN_ADD pfnSub = nullptr;



JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{

    void* handle = dlopen("/data/data/com.org.shell_elf/files/libfoo.so", RTLD_NOW);
    if (handle  == NULL)
    {
        printf("dlopen err:%s\n", dlerror());
        return JNI_VERSION_1_2;
    }

    PFN_ADD pAdd = (PFN_ADD)dlsym(handle,"Add");
    if (pAdd)
    {
        pfnAdd = pAdd;
    }

    PFN_ADD pSub=  (PFN_ADD)dlsym(handle,"Sub");
    if (pSub)
    {
        pfnSub = pSub;
    }
    //注册
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_2) != JNI_OK) {
        return -1;
    }

    auto clsMainActivity = env->FindClass("com/org/shell_elf/MainActivity");
    JNINativeMethod methods[] = {
            {"Add","(II)I",(void*)pfnAdd},
            {"Sub","(II)I",(void*)pfnSub}
    };
    env->RegisterNatives(clsMainActivity,methods,2);


    return JNI_VERSION_1_2;
}


extern "C"
JNIEXPORT jint JNICALL
Java_com_org_shell_1elf_MainActivity_test(JNIEnv *env, jobject thiz, jint n, jint n1) {
    // TODO: implement test()
}