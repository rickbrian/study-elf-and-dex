#include <stdio.h>
#include <link.h>
#include <string.h>
#include <memory.h>
#include <linux/elf.h>
#include <elf.h>
#include <sys/mman.h>
#include <errno.h>

int myPrintf(const char * __fmt, int n){
    printf("hook come om: __fmt:%s n:%d \n",__fmt,n);
    return printf(__fmt,n);
}

int DipCallback(struct dl_phdr_info* pDpi ,size_t,void* pData){

    printf("base:%p name:%s\n",pDpi->dlpi_addr,pDpi->dlpi_name);

    if(strstr(pDpi->dlpi_name,"main") != NULL){
        memcpy(pData,pDpi,sizeof(struct dl_phdr_info));
        return -1;
    }
    return 0;//继续遍历
}

__attribute__((constructor)) void hookPlt(){
    //1.获取main的模块基址
    struct  dl_phdr_info dpi = {0};
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
    uint64_t* pfnPrintf = NULL;
    for (size_t i = 0; i < nNumOfRelaPlt; i++)
    {
        uint32_t nSym = ELF64_R_SYM(pRelaPlt[i].r_info);

        if(strcmp(pszStrTab + pSymTab[nSym].st_name,"printf") == 0){
               pfnPrintf = (uint64_t*)(pRelaPlt[i].r_offset + dpi.dlpi_addr) ;
        }
    }
    
    //4.替换
    void* pPageBase = (void*)((uint64_t)pfnPrintf & (~0xFFFl));
    mprotect(pPageBase,1,PROT_WRITE | PROT_READ | PROT_EXEC);

    *pfnPrintf= (uint64_t)myPrintf;
    
    mprotect(pPageBase,1,PROT_READ);
}