#include <stdio.h>
#include <link.h>
#include <string.h>
#include <memory.h>
#include <linux/elf.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>
#include <dlfcn.h>


#define PAGE_BASE(x) ((void*)((u_int64_t)(x) & (~0xFFFl)))


/*
pfnDestAddr:要hook的函数地址
pfnNewAddr:hook函数
pfnOldAddr：旧函数地址
*/
void tramplo();
void* InlineHook(void* pfnDestAddr,  void* pfnNewAddr, void* pfnOldAddr){

    //1.申请内存，保存跳板代码
    size_t nLoadSize = 0x100;
    uint8_t *ptramplo = (uint8_t*)mmap64(NULL, nLoadSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS , -1, 0);
    mprotect(ptramplo,1 ,PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy((void*)ptramplo,(void*)tramplo,0xc0);

    uint8_t* ptramplo2 = ptramplo + 0x10;
    uint8_t* phookaddr = ptramplo + 0xc0;
    uint8_t* poldcode = ptramplo + 0xa0;
    uint8_t* poldaddr = ptramplo + 0xb8;
    //uint8_t* pretAddr = ptramplo + 0xc0;//返回的地址


    //2.保存原指令到oldcode
    memcpy((void*)poldcode,(void*)pfnDestAddr,16);

    //3.覆盖原指令为tramplo,并写入tramplo2的地址
    mprotect(PAGE_BASE(pfnDestAddr),1 ,PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy((void*)pfnDestAddr,(void*)ptramplo,16);
    memcpy(pfnDestAddr +8 ,(void*)&ptramplo2,8);

    //4.修改oldaddr为原指令地址
    void* pOldAddr = (uint8_t*)pfnDestAddr + 16;
    memcpy((void*)poldaddr,(void*)&pOldAddr,8);

    //5.填写hook的地址
    memcpy((void*)phookaddr,(void*)&pfnNewAddr,8);

    *(uint64_t*)pfnOldAddr = (uint64_t)poldcode;
    return poldcode;
}

//---------------------------------------------------------------
typedef int (*oldPfn)(const char* _Nonnull __fmt, ...);
oldPfn old_printf = NULL;

int myPrintf(const char * __fmt, int n){
    old_printf("inlinehook come om: __fmt:%s n:%d \n",__fmt,n);
    return 0;
}

//------------------------------------------------------------------
typedef int (*old_Pfnopen)(const char *pathname,const char * mode);
old_Pfnopen old_open= NULL;
int new_open(const char *pathname,const char *  mode) {
    printf("open hook  file path:%s %s \n", pathname,mode);

    return 0;
}

//------------------------------------
typedef int (*old_pfnPuts)(const char* _Nonnull __s);
old_pfnPuts old_puts= NULL;
int new_puts(const char* _Nonnull __s){
    printf("puts hook  :%s \n", __s);
    return 0;
}

__attribute__((constructor))  
void installInlineHook(){


    InlineHook(&printf,myPrintf,&old_printf);
    InlineHook(&fopen,new_open,&old_open);
    InlineHook(&puts,new_puts,&old_puts);

}