#include <stdio.h>
#include <link.h>
#include <string.h>
#include <memory.h>
#include <linux/elf.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>

#define PAGE_BASE(x) ((void*)((u_int64_t)(x) & (~0xFFFl)))

typedef int (*oldPfn)(const char* _Nonnull __fmt, ...);
oldPfn old_printf = NULL;

void tramplo();
int myPrintf(const char * __fmt, int n){
    old_printf("inlinehook come om: __fmt:%s n:%d \n",__fmt,n);
    return 0;
}

__attribute__((constructor)) void installInlineHook(){
    //1.获取hook 地址
    uint8_t* pPrintf = (uint8_t*)printf;

    uint8_t* ptramplo = (uint8_t*)tramplo;
    uint8_t* ptramplo2 = ptramplo + 0x10;
    uint8_t* poldcode = ptramplo + 0x9c;
    uint8_t* poldaddr = ptramplo + 0xB4;

    //2.保存原指令到oldcode
    mprotect(PAGE_BASE(poldcode),1 ,PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy((void*)poldcode,(void*)pPrintf,16);

    //3.覆盖原指令为tramplo,并写入tramplo2的地址
    mprotect(PAGE_BASE(pPrintf),1 ,PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy((void*)pPrintf,(void*)ptramplo,16);
    memcpy(pPrintf +8 ,(void*)&ptramplo2,8);

    //4.修改oldaddr为原指令地址
    void* pOldAddr = (uint8_t*)pPrintf + 16;
    memcpy((void*)poldaddr,(void*)&pOldAddr,8);

    old_printf = (oldPfn)poldcode;

}