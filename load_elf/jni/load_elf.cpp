//
// Created by PC on 2024/2/29.
//
#include "load_elf.h"



#define  PAGE_SIZE 0X1000
typedef struct elf64_hash
{
    uint32_t nbucket;
    uint32_t symindex;
    uint32_t mask_swords;
    uint32_t shift2;
    uint64_t* gnu_bloom_filter_;
    uint32_t* gnu_bucket_;
    uint32_t* gnu_chain_;
}Elf64_Hash;

int load_elf(const char* sz) {
    //1.读取文件，文件头和段表
    FILE *fp = fopen(sz, "rb");
    if (fp == NULL) {
        printf("open file error\n");
        return -1;
    }

    Elf64_Ehdr ehdr = {0};
    fread(&ehdr, 1, sizeof(Elf64_Ehdr), fp);
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("It is not elf file\n");
        return -1;
    }

    //1.2 读取段表
    size_t nSize = ehdr.e_phentsize * ehdr.e_phnum;
    Elf64_Phdr *phdr = (Elf64_Phdr *) malloc(nSize);
    if (phdr == NULL) {
        printf("malloc error\n");
        return -1;
    }
    fseek(fp, ehdr.e_phoff, SEEK_SET);
    fread(phdr, 1, nSize, fp);


    //2.申请内存，映射
    //2.1 计算内存大小
    size_t nLoadSize = 0;
    for (size_t i = ehdr.e_phnum - 1; i >= 0; i--) {
        if (phdr[i - 1].p_type == PT_LOAD) {
            nLoadSize =
                    ((phdr[i].p_vaddr + phdr[i].p_memsz + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
            break;
        }
    }

    //2.2 申请内存
    void *pBase = mmap64(NULL, nLoadSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    //2.3 加载段到程序中
    for (size_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            fseek(fp, phdr[i].p_offset, SEEK_SET);
            fread((char *) pBase + phdr[i].p_vaddr, 1, phdr[i].p_filesz, fp);
        }
    }

    if (phdr != NULL) {
        free(phdr);
    }
    fclose(fp);


    //3.定位动态段
    phdr = (Elf64_Phdr *) ((char *) pBase + ehdr.e_phoff);
    Elf64_Dyn *pDyn = NULL;
    size_t nNumOfDyn = 0;
    int nDynIndex = -1;
    for (size_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            pDyn = (Elf64_Dyn *) ((char *) pBase + phdr[i].p_vaddr);
            nNumOfDyn = phdr[i].p_memsz / sizeof(Elf64_Dyn);
            nDynIndex = i;
            break;
        }
    }

    //3.1解析动态段

    Elf64_Hash hash = {0};

    char *pszStrTab = NULL;

    Elf64_Sym *pSymTab = NULL;
    size_t nNumOfSym = 0;

    char *bufNeed[0x100] = {0};
    size_t nNumOfNeed = 0;

    Elf64_Rela *pRelaDyn = NULL;
    size_t nNumOfRela = 0;

    Elf64_Rela *pRelaPlt = NULL;
    size_t nNumOfRelaPlt = 0;


    while (pDyn->d_tag != DT_NULL) {
        switch (pDyn->d_tag) {
            case DT_STRTAB:
                pszStrTab = (char *) pBase + pDyn->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                pSymTab = (Elf64_Sym *) ((char *) pBase + pDyn->d_un.d_ptr);
                break;
            case DT_NEEDED:
                bufNeed[nNumOfNeed++] = pszStrTab + pDyn->d_un.d_val;
                break;
            case DT_RELA:
                pRelaDyn = (Elf64_Rela *) ((char *) pBase + pDyn->d_un.d_ptr);
                break;
            case DT_RELASZ:
                nNumOfRela = pDyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
            case DT_JMPREL:
                pRelaPlt = (Elf64_Rela *) ((char *) pBase + pDyn->d_un.d_ptr);
                break;
            case DT_PLTRELSZ:
                nNumOfRelaPlt = pDyn->d_un.d_val / sizeof(Elf64_Rela);
                break;
            case DT_GNU_HASH: {
                uint8_t *pHashTable = (uint8_t *) pBase + pDyn->d_un.d_ptr;
                hash.nbucket = ((uint32_t *) pHashTable)[0];
                hash.symindex = ((uint32_t *) pHashTable)[1];
                hash.mask_swords = ((uint32_t *) pHashTable)[2];
                hash.shift2 = ((uint32_t *) pHashTable)[3];

                hash.gnu_bloom_filter_ = (uint64_t *) (pHashTable + 16);
                hash.gnu_bucket_ = (uint32_t *) (hash.gnu_bloom_filter_ + hash.mask_swords);
                hash.gnu_chain_ = hash.gnu_bucket_ + hash.nbucket;
                break;
            }
            default:
                break;
        }
        pDyn++;
    }

    //4.重定位表
    //4.1 重定位

    return 0;
}

int main() {
    load_elf("/data/local/tmp/libfoo.so");

    return 0;
}