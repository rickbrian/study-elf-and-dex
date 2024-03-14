//
// Created by PC on 2024/2/29.
//
#include "load_elf.h"

typedef void*(*PFN_INIT)();



#define ElfW(type) Elf64_##type 

typedef uint64_t linker_ctor_function_t; 
typedef uint64_t linker_dtor_function_t;

struct link_map
{
    ElfW(Addr) l_addr;
    char *l_name;
    ElfW(Dyn) * l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
};
struct TlsIndex {
    size_t module_id;
    size_t offset;
};
struct TlsSegment {
    size_t size = 0;
    size_t alignment = 1;
    const void* init_ptr = "";
    size_t init_size = 0;
};
struct soinfo_tls {
    TlsSegment segment;
    size_t module_id ;
};
struct TlsDynamicResolverArg {
    size_t generation;
    TlsIndex index;
};
template<typename T  ,typename Allocator>
class LinkedList
{
    void * head_ ;
    void* tail_ ;
};

typedef LinkedList<int, void*> soinfo_list_t;
typedef LinkedList<int, void*> android_namespace_list_t;


struct soinfo
{
public:
    const ElfW(Phdr) * phdr;
    size_t phnum;
    uint64_t* base;
    size_t size;
    ElfW(Dyn) * dynamic;
    soinfo *next;
    uint32_t flags_;

    const char *strtab_;
    ElfW(Sym) * symtab_;

    size_t nbucket_;
    size_t nchain_;
    uint32_t *bucket_;
    uint32_t *chain_;

    ElfW(Rela) * plt_rela_;
    size_t plt_rela_count_;

    ElfW(Rela) * rela_;
    size_t rela_count_;

    linker_ctor_function_t *preinit_array_;
    size_t preinit_array_count_;

    linker_ctor_function_t *init_array_;
    size_t init_array_count_;
    linker_dtor_function_t *fini_array_;
    size_t fini_array_count_;

    linker_ctor_function_t init_func_;
    linker_dtor_function_t fini_func_;

    size_t ref_count_;
    link_map link_map_head;

    bool constructors_called;

    // When you read a virtual address from the ELF file, add this
    // value to get the corresponding address in the process' address space.
    uint64_t* load_bias;

    bool has_DT_SYMBOLIC;

    uint32_t version_;

    // version >= 0
    dev_t st_dev_;
    ino_t st_ino_;

    // dependency graph
    soinfo_list_t children_;
    soinfo_list_t parents_;

    // version >= 1
    off64_t file_offset_;
    uint32_t rtld_flags_;
    uint32_t dt_flags_1_;
    size_t strtab_size_;

    // version >= 2

    size_t gnu_nbucket_;
    uint32_t *gnu_bucket_;
    uint32_t *gnu_chain_;
    uint32_t gnu_maskwords_;
    uint32_t gnu_shift2_;
    uint64_t * gnu_bloom_filter_;

    soinfo *local_group_root_;

    uint8_t *android_relocs_;
    size_t android_relocs_size_;

    const char *soname_;
    std::string realpath_;

    const ElfW(Versym) * versym_;

    ElfW(Addr) verdef_ptr_;
    size_t verdef_cnt_;

    Elf64_Addr verneed_ptr_;
    size_t verneed_cnt_;

    int target_sdk_version_;

    // version >= 3
    std::vector<std::string> dt_runpath_;
    void*primary_namespace_;
    android_namespace_list_t secondary_namespaces_;
    uintptr_t handle_;

    // version >= 4
    ElfW(Relr) * relr_;
    size_t relr_count_;

    // version >= 5
    std::unique_ptr<soinfo_tls> tls_;
    std::vector<TlsDynamicResolverArg> tlsdesc_args_;
};



typedef soinfo* (*PFN_find_containing_library)(const void* p);

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

__attribute__((noinline))
void* getLinker64Base(){
    pid_t pid = getpid();
    int nStarAddr =  0;
    char szName[0x100] = {0};

    sprintf(szName, "/proc/%d/maps", pid);
    puts(szName);
    FILE  *pFile = fopen(szName, "r");
    if (!pFile) {
        fprintf(stderr, "Error opening file.\n");
        return NULL;
    }
    while (!feof(pFile)) {
        char szLine[0x100] = {0};
        fgets(szLine, sizeof(szLine), pFile);
        if(strstr(szLine, "linker64")){
            // Assuming the address is the first part of the line before the '-' character
            char* addrStr = strtok(szLine, "-");
            if (addrStr) {
                return (void*)strtoul(addrStr, NULL, 16);
                
            }
        }

    }

    fclose(pFile);

    return NULL;
}

__attribute__((noinline))
uint32_t gnu_hash(const char* name) {
    uint32_t h = 5381;
    while (*name != 0) {
        h += (h << 5) + *name++; // h*33 + c = h + h * 32 + c = h + h << 5 + c
    }

    return h;
}
Elf64_Hash g_hash = {0};
Elf64_Sym *pSymTab = NULL;
char *pszStrTab = NULL;
__attribute__((noinline))
void* myDlsym(void* pBase , const char* szName)
{
    uint32_t nHash = gnu_hash(szName);
    uint32_t h2 = nHash >> g_hash.shift2;

    uint32_t bloom_mask_bits = 64;
    uint32_t word_num = (nHash / bloom_mask_bits) & g_hash.mask_swords;
    uint64_t bloom_word = g_hash.gnu_bloom_filter_[word_num];

    if ((1 & (bloom_word >> (nHash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
      return NULL;
    }

    uint32_t n = g_hash.gnu_bucket_[nHash % g_hash.nbucket];

    do
    {
        Elf64_Sym* s = pSymTab + n;
        if (((g_hash.gnu_chain_[n] ^ nHash) >> 1) == 0 &&
            strcmp(pszStrTab + s->st_name, szName) == 0 )
        {
            return (void*)((uint8_t*)pBase + s->st_value);
        }
    } while ((g_hash.gnu_chain_[n++] & 1) == 0);

    return NULL;
}

__attribute__((noinline))
void Relacate(uint8_t* pBase, Elf64_Rela* pRel ,size_t nNumOfRels, Elf64_Sym* pSym,
    void* hSos[], size_t nNumOfSos, const char* pStr){
        for (size_t i = 0; i < nNumOfRels; i++)
        {
            uint32_t nSym = ELF64_R_SYM(pRel[i].r_info);
            uint32_t nType = ELF64_R_TYPE(pRel[i].r_info);

            //根据符号获取地址
            void *nAddr = NULL;
            if( pSym[nSym].st_value  != 0 ){
                //导出符号，自己模块内部的符号
                nAddr = pBase + pSym[nSym].st_value;
            }
            else{
                for (size_t i = 0; i < nNumOfSos; i++)
                {
                    nAddr = dlsym(hSos[i],pStr + pSym[nSym].st_name);
                    if(nAddr != NULL){
                        break;
                    }
                }
                
            }

            switch (nType)
            {
            case R_AARCH64_RELATIVE:
                *(uint64_t*)(pBase + pRel[i].r_offset) = (uint64_t)(pBase + pRel[i].r_addend);
                break;
            case R_AARCH64_GLOB_DAT://全局变量
                *(uint64_t*)(pBase + pRel[i].r_offset) = (uint64_t)nAddr;
                break;
            case R_AARCH64_JUMP_SLOT://函数
                *(uint64_t*)(pBase + pRel[i].r_offset) = (uint64_t)nAddr;
                break;
            case R_AARCH64_ABS64://init_array
                *(uint64_t*)(pBase + pRel[i].r_offset) = (uint64_t)nAddr;
                break;
            default:
                break;
            }
        }
        
}

__attribute__((noinline))
void* load_elf(const char* sz) {
    //1.读取文件，文件头和段表
    FILE *fp = fopen(sz, "rb");
    if (fp == NULL) {
        printf("open file error\n");
        return NULL;
    }

    Elf64_Ehdr ehdr = {0};
    fread(&ehdr, 1, sizeof(Elf64_Ehdr), fp);
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        printf("It is not elf file\n");
        return NULL;
    }

    //1.2 读取段表
    size_t nSize = ehdr.e_phentsize * ehdr.e_phnum;
    Elf64_Phdr *phdr = (Elf64_Phdr *) malloc(nSize);
    if (phdr == NULL) {
        printf("malloc error\n");
        return NULL;
    }
    fseek(fp, ehdr.e_phoff, SEEK_SET);
    fread(phdr, 1, nSize, fp);


    //2.申请内存，映射
    //2.1 计算内存大小,需要申请一个完整的分页
    size_t nLoadSize = 0;
    for (size_t i = ehdr.e_phnum - 1; i >= 0; i--) {
        if (phdr[i].p_type == PT_LOAD) {
            nLoadSize =
                    ((phdr[i].p_vaddr + phdr[i].p_memsz + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
            break;
        }
    }

    //2.2 申请内存
    uint8_t *pBase = (uint8_t*)mmap64(NULL, nLoadSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS , -1, 0);

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
    Elf64_Dyn *pDyns = pDyn;
    //3.1解析动态段
    size_t nSizeOfStrtable = 0;

    size_t nNumOfSym = 0;

    char *bufNeed[0x100] = {0};
    size_t nNumOfNeed = 0;

    Elf64_Rela *pRelaDyn = NULL;
    size_t nNumOfRela = 0;

    Elf64_Rela *pRelaPlt = NULL;
    size_t nNumOfRelaPlt = 0;

    PFN_INIT* bufInis = NULL;
    size_t nNumOfInis = 0;

    Elf64_Versym * pVERSYM = NULL;
    Elf64_Addr pVERNEED = NULL;
    size_t nVERNEEDNUM = 0;

    while (pDyn->d_tag != DT_NULL) {
        switch (pDyn->d_tag) {
            case DT_STRTAB:
                pszStrTab = (char *) pBase + pDyn->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                pSymTab = (Elf64_Sym *) ((char *) pBase + pDyn->d_un.d_ptr);
                break;
            case DT_NEEDED:
                bufNeed[nNumOfNeed++] =  (char*)pDyn->d_un.d_val;
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
                g_hash.nbucket = ((uint32_t *) pHashTable)[0];
                g_hash.symindex = ((uint32_t *) pHashTable)[1];
                g_hash.mask_swords = ((uint32_t *) pHashTable)[2];
                g_hash.shift2 = ((uint32_t *) pHashTable)[3];

                g_hash.gnu_bloom_filter_ = (uint64_t *) (pHashTable + 16);
                g_hash.gnu_bucket_ = (uint32_t *) (g_hash.gnu_bloom_filter_ + g_hash.mask_swords);
                g_hash.gnu_chain_ = g_hash.gnu_bucket_ + g_hash.nbucket - g_hash.symindex;

                --g_hash.mask_swords;//源码中就是这样的
                break;
            }
            case DT_INIT_ARRAY:
                bufInis = (PFN_INIT*)(pBase + pDyn->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                nNumOfInis =  pDyn->d_un.d_val / sizeof(void*);
                break;
            case DT_STRSZ:
                nSizeOfStrtable = pDyn->d_un.d_ptr;
                break;
            case DT_VERNEED:
                pVERNEED =  (Elf64_Addr)(pBase + pDyn->d_un.d_ptr);
                break;
            case DT_VERNEEDNUM:
                nVERNEEDNUM = pDyn->d_un.d_ptr;
                break;
            case DT_VERSYM:
                pVERSYM = (Elf64_Versym*)(pBase + pDyn->d_un.d_ptr);
                break;
            default:
                break;
        }
        pDyn++;
    }


    //4.重定位表
    //4.1加载模块
    void** hSos = (void**)malloc(sizeof(void*)*nNumOfNeed);
    for (size_t i = 0; i < nNumOfNeed; i++)
    {
        bufNeed[i] = (uint64_t)bufNeed[i] + pszStrTab ;
        hSos[i] = dlopen(bufNeed[i],RTLD_NOW);
    }
    

    //4.1 重定位
    Relacate(pBase,pRelaDyn,nNumOfRela,pSymTab,hSos,nNumOfNeed,pszStrTab);
    Relacate(pBase,pRelaPlt,nNumOfRelaPlt,pSymTab,hSos,nNumOfNeed,pszStrTab);


    //5.修复sinfo
    printf("修复sinfo\n");
    void*pLinkerBase = getLinker64Base();
    printf("pLinkerBase:%llx\n",pLinkerBase);
    if(pLinkerBase == NULL){
        printf("getLinker64Base failed\n");
        return NULL;
    }
    PFN_find_containing_library pfn_find_containing_library =
        (PFN_find_containing_library)((int8_t *)pLinkerBase + 0x38F14);//安卓10
    soinfo *pSo = pfn_find_containing_library((void *)&myDlsym);
    printf("soinfo addr:%llx\n",pSo);
    pSo->phdr = phdr;
    pSo->phnum = ehdr.e_phnum;
    pSo->base = (uint64_t*)pBase;
    pSo->size = nLoadSize;
    pSo->dynamic = pDyns;
    pSo->strtab_ = pszStrTab;
    pSo->symtab_ = pSymTab;
    pSo->plt_rela_ = pRelaPlt;
    pSo->plt_rela_count_ = nNumOfRelaPlt;
    pSo->rela_ = pRelaDyn;
    pSo->rela_count_ = nNumOfRela;

    //preinit_array_
    //preinit_array_count_

    pSo->init_array_ = (linker_ctor_function_t *)bufInis;
    pSo->init_array_count_ = nNumOfInis;

    //fini_array_
    //fini_array_count_

    pSo->load_bias = (uint64_t*)pBase;
    pSo->strtab_size_ = nSizeOfStrtable;

    pSo->gnu_nbucket_   = g_hash.nbucket;
    pSo->gnu_bucket_ = g_hash.gnu_bucket_;
    pSo->gnu_chain_ = g_hash.gnu_chain_;
    pSo->gnu_maskwords_ = g_hash.mask_swords;
    pSo->gnu_shift2_ = g_hash.shift2;
    pSo->gnu_bloom_filter_ = g_hash.gnu_bloom_filter_;

    pSo->versym_ = pVERSYM;
    pSo->verneed_ptr_ = pVERNEED;
    pSo->verneed_cnt_ = nVERNEEDNUM;

    
    //6.初始函数
    for (size_t i = 0; i < nNumOfInis; i++)
    {
        bufInis[i]();
    }
    

    return pBase;
}

__attribute__ ((constructor)) void load()
{
    printf("load\n");
    void* handle = load_elf("/data/local/tmp/libtest.so");
    typedef int*(*PFN_ADD)(int,int);

    PFN_ADD pAdd = (PFN_ADD)myDlsym(handle,"Add");
    if (pAdd)
    {
        printf("\n1 + 3 = %d \n",pAdd(1,3));
    }
    else{
        printf("myDlsym err:%s\n", dlerror());
    }
}