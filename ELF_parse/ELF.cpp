//
// Created by PC on 2024/2/29.
//


#include <cstdio>
#include <String>
#include <string.h>
#include "ELF.h"
#include "elf-h.h"

ELF::ELF(const char *file_path) {
    //读取文件数据
    FILE *file = fopen(file_path, "rb");
    if (file == nullptr) {
        printf("open file error\n");
        return;
    }
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    //分配内存
    m_elfData = new char[fileSize];
    fread(m_elfData, 1, fileSize, file);
    fclose(file);

}

ELF::~ELF() {
    //释放资源
    if (m_elfData != nullptr) {
        delete[] m_elfData;
        m_elfData = nullptr;
    }
}



void ELF::get_elf_header() const {
    //获取文件头的信息
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    printf("====================文件头：=======================\n");
    //printf("e_ident: %s\n", ehdr->e_ident);
    //解析e_ident
    char str_elf[4] = {(char)(ehdr->e_ident[1]), (char)((ehdr->e_ident[2])), (char)(ehdr->e_ident[3]),0};
    printf("模数: 0x%X %s\n", ehdr->e_ident[0],str_elf);
    printf("位：%s\n", parse_el_class(ehdr->e_ident[EI_CLASS]));
    printf("编码：%s\n", parse_el_data(ehdr->e_ident[EI_DATA]));

    printf("类型: %s\n", parse_type(ehdr->e_type));
    printf("机器: %s\n", pare_em_machine(ehdr->e_machine));
    printf("版本: %d\n", ehdr->e_version);
    printf("程序入口: 0x%llu\n", ehdr->e_entry);
    printf("段表偏移: 0x%llx\n", ehdr->e_phoff);
    printf("节表偏移: 0x%llx\n", ehdr->e_shoff);
    printf("标志: %d\n", ehdr->e_flags);
    printf("文件头大小: 0x%x\n", ehdr->e_ehsize);
    printf("段表每项大小: %d\n", ehdr->e_phentsize);
    printf("段表的项数: %d\n", ehdr->e_phnum);
    printf("节表每项大小: %d\n", ehdr->e_shentsize);
    printf("节表的项数: %d\n", ehdr->e_shnum);
    printf("字符表在节表中的索引: %d\n", ehdr->e_shstrndx);


}

void ELF::get_section_header() const {
    //获取节表的信息
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    auto *strtab = (char *) (m_elfData + shdr[ehdr->e_shstrndx].sh_offset);
    printf("====================节表：=======================\n");
    printf("索引     名称                     类型                   地址     偏移     大小     链接    信息     对齐     表项大小\n");
    for (int i = 0; i < ehdr->e_shnum; i++) {

        printf("%d\t%-20s\t%-20s\t0x%llx\t0x%llx\t0x%llx\t%d\t%d\t0x%llx\t%llu\n", i, strtab + shdr[i].sh_name,
               parse_section_type(shdr[i].sh_type), shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_link, shdr[i].sh_info,
               shdr[i].sh_addralign, shdr[i].sh_entsize);
    }
}

int ELF::get_str_index(const char *name ) const {
    //获取字符串表的索引
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    auto *strtab = (char *) (m_elfData + shdr[ehdr->e_shstrndx].sh_offset);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (strcmp(strtab + shdr[i].sh_name, name) == 0) {
            return i;
        }
    }
    return -1;
}
void ELF::get_symbol_table() const {
    //获取符号表的信息
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    int index = get_str_index(".strtab");
    auto *strtab = (char *) (m_elfData + shdr[index].sh_offset);
    printf("====================符号表(.symtab)：=======================\n");
    printf("索引     名称                     类型                   绑定         可见性     节索引     值     大小\n");
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB) {
            auto *sym = (Elf64_Sym *) (m_elfData + shdr[i].sh_offset);
            int sym_num = shdr[i].sh_size / shdr[i].sh_entsize;
            for (int j = 0; j < sym_num; j++) {
                printf("%d\t%-25s\t%-10s\t%-10s\t%hhd\t0x%X\t0x%llx\t%llu\n", j, strtab + sym[j].st_name,
                       parse_symbol_type(sym[j].st_info), parse_symbol_bind(sym[j].st_info), (sym[j].st_other),
                       sym[j].st_shndx, sym[j].st_value, sym[j].st_size);
            }
        }
    }
}



void ELF::get_dynamic_symbol_table() const {
    //获取符号表的信息
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    int index = get_str_index(".dynstr");
    auto *strtab = (char *) (m_elfData + shdr[index].sh_offset);
    printf("====================符号表(.dynamic)：=======================\n");
    printf("索引     名称                     类型                    绑定         可见性     节索引     值     大小\n");
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_DYNSYM) {
            auto *sym = (Elf64_Sym *) (m_elfData + shdr[i].sh_offset);
            int sym_num = shdr[i].sh_size / shdr[i].sh_entsize;
            for (int j = 0; j < sym_num; j++) {
                printf("%d\t%-25s\t%-10s\t%-10s\t%hhd\t0x%X\t0x%llx\t%llu\n", j, strtab + sym[j].st_name,
                       parse_symbol_type(sym[j].st_info), parse_symbol_bind(sym[j].st_info), (sym[j].st_other),
                       sym[j].st_shndx, sym[j].st_value, sym[j].st_size);
            }
        }
    }
}

char str[0x10] = {0};
char* parse_program_flags(Elf64_Word p_flags){
    //解析段表的标志

    memset(str, 0, sizeof(str));
    if (p_flags & PF_R)
    {
        strcat(str, "R");
    }
    if(p_flags & PF_W)
    {
        strcat(str, "W");
    }
    if(p_flags & PF_X)
    {
        strcat(str, "X");
    }
    return str;

}

void ELF::get_program_header() const {
    //解析段表
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *phdr = (Elf64_Phdr *) (m_elfData + ehdr->e_phoff);
    auto len = ehdr->e_phnum;
    printf("====================段表：=======================\n");
    printf("类型        内存属性   偏移            虚拟地址        物理地址          文件大小          内存大小         标志     对齐\n");
    for (int i = 0; i <len; ++i) {
        printf("%-13s%-8s0x%llx\t\t0x%llx\t\t0x%llx\t\t0x%llx\t\t0x%llx\t\t0x%x\t0x%llx\n",
               parse_segment_type(phdr[i].p_type), parse_program_flags(phdr[i].p_flags), phdr[i].p_offset, phdr[i].p_vaddr, phdr[i].p_paddr, phdr[i].p_filesz, phdr[i].p_memsz, phdr[i].p_flags, phdr[i].p_align);

        if( phdr[i].p_type == PT_INTERP){
            printf("[Requesting program interpreter: %s ]\n",phdr[i].p_offset + m_elfData);
        }

    }

}

void printHex(char * sz,int len){
    for (int i = 0; i < len; ++i) {
        printf("%02x ", sz[i] & 0XFF);
    }
}

void ELF::get_program_note() const {
    //解析段表注释节
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *phdr = (Elf64_Phdr *) (m_elfData + ehdr->e_phoff);
    auto len = ehdr->e_phnum;
    printf("============================注释节==============================");
    for (int i = 0; i < len; ++i) {
        if(phdr[i].p_type == PT_NOTE){
            //解析
            Elf64_Nhdr* nhdr = (Elf64_Nhdr*)(m_elfData + phdr[i].p_offset);
            printf("wner                Data size              Data\n");
            for (int j = 0; j < 2; ++j) {
                printf("%s 0x%X    ", (nhdr + 1), nhdr->n_descsz);
                printHex((char*)nhdr + sizeof (Elf64_Nhdr) + nhdr->n_namesz,nhdr->n_descsz);
                nhdr = (Elf64_Nhdr*)((char*)nhdr + sizeof (Elf64_Nhdr) + nhdr->n_namesz + nhdr->n_descsz);
                printf("\n");
            }

        }
    }

}

void ELF::get_rela_dyn() const {
    //获取.rela.dyn表的信息
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    int index = get_str_index(".rela.dyn");
    Elf64_Rela *rela = (Elf64_Rela *) (m_elfData + shdr[index].sh_offset);
    int str_index = get_str_index(".dynstr");
    auto *strtab = (char *) (m_elfData + shdr[str_index].sh_offset);
    printf("=====================.rela.dyn===================================\n");
    printf("Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n");
    for (int i = 0; i < shdr[index].sh_size / shdr[index].sh_entsize  ; ++i) {

        printf("%016llx  %016llx  %s  %20llx",rela[i].r_offset,rela[i].r_info,parse_rela_info_type(rela[i].r_info),rela[i].r_addend);
        int n = ELF64_R_SYM(rela[i].r_info)== 0 ? 0 : ELF64_R_SYM(rela[i].r_info);
        if(n != 0){
            for (int i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_type == SHT_DYNSYM) {
                    auto *sym = (Elf64_Sym *) (m_elfData + shdr[i].sh_offset);
                    printf(" %s",n== 0 ? (char*) "" : (char*)(strtab + sym[n].st_name));
                }
            }
        }
        printf("\n");
    }
}

void ELF::get_rela_plt() const {
    //获取.rela.plt表的信息
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    int index = get_str_index(".rela.plt");
    Elf64_Rela *rela = (Elf64_Rela *) (m_elfData + shdr[index].sh_offset);
    int str_index = get_str_index(".dynstr");
    auto *strtab = (char *) (m_elfData + shdr[str_index].sh_offset);
    printf("=====================.rela.plt===================================\n");
    printf("Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n");
    for (int i = 0; i < shdr[index].sh_size / shdr[index].sh_entsize  ; ++i) {

        printf("%016llx  %016llx  %s  %20llx",rela[i].r_offset,rela[i].r_info,parse_rela_info_type(rela[i].r_info),rela[i].r_addend);
        int n = ELF64_R_SYM(rela[i].r_info)== 0 ? 0 : ELF64_R_SYM(rela[i].r_info);
        if(n != 0){
            for (int i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_type == SHT_DYNSYM) {
                    auto *sym = (Elf64_Sym *) (m_elfData + shdr[i].sh_offset);
                    printf(" %s",n== 0 ? (char*) "" : (char*)(strtab + sym[n].st_name));
                }
            }
        }
        printf("\n");
    }
}

void ELF::get_dynamic_section() const {
    //段表中找PT_DYNAMIC
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *phdr = (Elf64_Phdr *) (m_elfData + ehdr->e_phoff);
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    auto len = ehdr->e_phnum;
    printf("====================动态节(Dynamic section)：=======================\n");
    for (int i = 0; i < len; ++i) {
        if(phdr[i].p_type == PT_DYNAMIC){
            //解析
            Elf64_Dyn* dyn = (Elf64_Dyn*)(m_elfData + phdr[i].p_offset);
            printf("Tag                Type              Name/Value\n");
            do{
                printf("0x%016llx %-20s 0x%llx ", dyn->d_tag, parse_dynamic_tag(dyn->d_tag), dyn->d_un.d_val);
                if(dyn->d_tag == DT_NEEDED){
                    int str_index = get_str_index(".dynstr");
                    auto *strtab = (char *) (m_elfData + shdr[str_index].sh_offset);
                    printf("Shared library: [%s]",strtab + dyn->d_un.d_val);
                }
                if(dyn->d_tag == DT_SONAME){
                    int str_index = get_str_index(".dynstr");
                    auto *strtab = (char *) (m_elfData + shdr[str_index].sh_offset);
                    printf("Library soname: [%s]",strtab + dyn->d_un.d_val);
                }
                dyn++;
                printf("\n");
            } while (dyn->d_tag != DT_NULL);

        }
    }

}
