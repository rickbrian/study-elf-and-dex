#include <stdio.h>
#include <link.h>
#include <string.h>
#include <memory.h>
#include <linux/elf.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>


int DipCallback(struct dl_phdr_info* pDpi ,size_t,void* pData){

    printf("base:%p name:%s\n",pDpi->dlpi_addr,pDpi->dlpi_name);

    if(strstr(pDpi->dlpi_name,((struct dl_phdr_info*)pData)->dlpi_name) != NULL){
        memcpy(pData,pDpi,sizeof(struct dl_phdr_info));
        return -1;
    }
    return 0;//继续遍历
}


void* PltHook(const char* szModuleName,  const char* szSymName, void* pNewFund){
    //1.获取main的模块基址
    struct  dl_phdr_info dpi = {0};
    dpi.dlpi_name = szModuleName;
    dl_iterate_phdr(DipCallback,&dpi);
    printf("find base:%p name:%s\n",dpi.dlpi_addr,dpi.dlpi_name);


    
    //2.解析文件格式，获取重定位表
    Elf64_Dyn *pDyn = NULL;
    for (size_t i = 0; i < dpi.dlpi_phnum; i++) {
        if (dpi.dlpi_phdr[i].p_type == PT_DYNAMIC) {
            pDyn = (Elf64_Dyn *) ((char *) dpi.dlpi_addr + dpi.dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    char* pszStrTab = NULL;

    Elf64_Sym *pSymTab = NULL;

    Elf64_Rela *pRelaDyn = NULL;
    size_t nNumOfRela = 0;

    Elf64_Rela * pRelaPlt = NULL;
    size_t nNumOfRelaPlt = 0;

    while (pDyn->d_tag != DT_NULL) {
        switch (pDyn->d_tag) {
            case DT_STRTAB:
                pszStrTab = (char *) dpi.dlpi_addr + pDyn->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                pSymTab = (Elf64_Sym *) ((char *) dpi.dlpi_addr + pDyn->d_un.d_ptr);
                break;
            case DT_RELA:
                pRelaDyn = (Elf64_Rela *) ((char *) dpi.dlpi_addr + pDyn->d_un.d_ptr);
                break;
            case DT_RELASZ:
                nNumOfRela = pDyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
            case DT_JMPREL:
                pRelaPlt = (Elf64_Rela *) ((char *) dpi.dlpi_addr + pDyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                nNumOfRelaPlt = pDyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
            default:
            break;
        }
        pDyn++;
    }

    //3.遍历重定位表，定位printf的地址
    uint64_t* pfnFun = NULL;
    for (size_t i = 0; i < nNumOfRelaPlt; i++)
    {
        uint32_t nSym = ELF64_R_SYM(pRelaPlt[i].r_info);

        if(strcmp(pszStrTab + pSymTab[nSym].st_name,szSymName) == 0){
               pfnFun = (uint64_t*)(pRelaPlt[i].r_offset + dpi.dlpi_addr) ;
        }
    }
    
    //4.替换
    void* pPageBase = (void*)((uint64_t)pfnFun & (~0xFFFl));
    mprotect(pPageBase,1,PROT_WRITE | PROT_READ | PROT_EXEC);

    //*pfnPrintf= (uint64_t)myPrintf;
    uint64_t oldFund = *pfnFun;
    *pfnFun= (uint64_t)pNewFund;
    
    mprotect(pPageBase,1,PROT_READ);

    return (void*)oldFund;
}

//------------------printf-----------------
typedef int (*oldPfn)(const char * __fmt, int n);
oldPfn old_printf = NULL;

int myPrintf(const char * __fmt, int n){
    printf("hook come om: __fmt:%s n:%d \n",__fmt,n);
    return old_printf(__fmt,n);
}

//-----------------fopen------------------
typedef int (*old_Pfnopen)(const char *pathname,const char * mode);
old_Pfnopen old_open= NULL;
int new_open(const char *pathname,const char *  mode) {
    printf("open hook  file path:%s %s \n", pathname,mode);
    int result = old_open(pathname, mode);
    printf("open result:%d \n", result);

    return result;
}

__attribute__((constructor)) void hookPlt(){
    old_printf = (oldPfn)PltHook("main", "printf", (void*)myPrintf);
    
    old_open = (old_Pfnopen)PltHook("main", "fopen", (void*)new_open);
}




