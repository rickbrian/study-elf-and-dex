#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    // void* handle = load_elf("/data/local/tmp/libfoo1111111111222.so");

    typedef int*(*PFN_ADD)(int,int);

    // PFN_ADD pAdd = (PFN_ADD)myDlsym(handle,"Add");
    // if (pAdd)
    // {
    //     printf("1 + 3 = %d ",pAdd(1,3));
    // }
    
    // PFN_ADD pSub=  (PFN_ADD)myDlsym(handle,"Sub");
    // if (pSub)
    // {
    //     printf("1 - 3 = %d ",pSub(1,3));
    // }

    //动态加载库
    void* handle  = dlopen("/data/local/tmp/libfoo.so", RTLD_NOW);
    if (handle  == NULL)
    {
        printf("dlopen err:%s\n", dlerror());
        return 0;
    }

    //获取函数地址
    PFN_ADD pfn = dlsym(handle, "Add");
    if (pfn == NULL)
    {
        printf("dlsym err:%s\n", dlerror());
        return 0;
    }

    printf("1+3=%d \n", pfn(1, 3));


    return 0;
}
