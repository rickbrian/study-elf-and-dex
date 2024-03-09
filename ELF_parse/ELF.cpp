//
// Created by PC on 2024/2/29.
//


#include <cstdio>
#include <String>
#include <string.h>
#include "ELF.h"
#include "elf-h.h"

ELF::ELF(const char *file_path) {
    //��ȡ�ļ�����
    FILE *file = fopen(file_path, "rb");
    if (file == nullptr) {
        printf("open file error\n");
        return;
    }
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    //�����ڴ�
    m_elfData = new char[fileSize];
    fread(m_elfData, 1, fileSize, file);
    fclose(file);

}

ELF::~ELF() {
    //�ͷ���Դ
    if (m_elfData != nullptr) {
        delete[] m_elfData;
        m_elfData = nullptr;
    }
}



void ELF::get_elf_header() const {
    //��ȡ�ļ�ͷ����Ϣ
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    printf("====================�ļ�ͷ��=======================\n");
    //printf("e_ident: %s\n", ehdr->e_ident);
    //����e_ident
    char str_elf[4] = {(char)(ehdr->e_ident[1]), (char)((ehdr->e_ident[2])), (char)(ehdr->e_ident[3]),0};
    printf("ģ��: 0x%X %s\n", ehdr->e_ident[0],str_elf);
    printf("λ��%s\n", parse_el_class(ehdr->e_ident[EI_CLASS]));
    printf("���룺%s\n", parse_el_data(ehdr->e_ident[EI_DATA]));

    printf("����: %s\n", parse_type(ehdr->e_type));
    printf("����: %s\n", pare_em_machine(ehdr->e_machine));
    printf("�汾: %d\n", ehdr->e_version);
    printf("�������: 0x%llu\n", ehdr->e_entry);
    printf("�α�ƫ��: 0x%llx\n", ehdr->e_phoff);
    printf("�ڱ�ƫ��: 0x%llx\n", ehdr->e_shoff);
    printf("��־: %d\n", ehdr->e_flags);
    printf("�ļ�ͷ��С: 0x%x\n", ehdr->e_ehsize);
    printf("�α�ÿ���С: %d\n", ehdr->e_phentsize);
    printf("�α������: %d\n", ehdr->e_phnum);
    printf("�ڱ�ÿ���С: %d\n", ehdr->e_shentsize);
    printf("�ڱ������: %d\n", ehdr->e_shnum);
    printf("�ַ����ڽڱ��е�����: %d\n", ehdr->e_shstrndx);


}

void ELF::get_section_header() const {
    //��ȡ�ڱ����Ϣ
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    auto *strtab = (char *) (m_elfData + shdr[ehdr->e_shstrndx].sh_offset);
    printf("====================�ڱ�=======================\n");
    printf("����     ����                     ����                   ��ַ     ƫ��     ��С     ����    ��Ϣ     ����     �����С\n");
    for (int i = 0; i < ehdr->e_shnum; i++) {

        printf("%d\t%-20s\t%-20s\t0x%llx\t0x%llx\t0x%llx\t%d\t%d\t0x%llx\t%llu\n", i, strtab + shdr[i].sh_name,
               parse_section_type(shdr[i].sh_type), shdr[i].sh_addr, shdr[i].sh_offset, shdr[i].sh_size, shdr[i].sh_link, shdr[i].sh_info,
               shdr[i].sh_addralign, shdr[i].sh_entsize);
    }
}

int ELF::get_str_index(const char *name ) const {
    //��ȡ�ַ����������
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
    //��ȡ���ű����Ϣ
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    int index = get_str_index(".strtab");
    auto *strtab = (char *) (m_elfData + shdr[index].sh_offset);
    printf("====================���ű�(.symtab)��=======================\n");
    printf("����     ����                     ����                   ��         �ɼ���     ������     ֵ     ��С\n");
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
    //��ȡ���ű����Ϣ
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    int index = get_str_index(".dynstr");
    auto *strtab = (char *) (m_elfData + shdr[index].sh_offset);
    printf("====================���ű�(.dynamic)��=======================\n");
    printf("����     ����                     ����                    ��         �ɼ���     ������     ֵ     ��С\n");
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
    //�����α�ı�־

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
    //�����α�
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *phdr = (Elf64_Phdr *) (m_elfData + ehdr->e_phoff);
    auto len = ehdr->e_phnum;
    printf("====================�α�=======================\n");
    printf("����        �ڴ�����   ƫ��            �����ַ        �����ַ          �ļ���С          �ڴ��С         ��־     ����\n");
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
    //�����α�ע�ͽ�
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *phdr = (Elf64_Phdr *) (m_elfData + ehdr->e_phoff);
    auto len = ehdr->e_phnum;
    printf("============================ע�ͽ�==============================");
    for (int i = 0; i < len; ++i) {
        if(phdr[i].p_type == PT_NOTE){
            //����
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
    //��ȡ.rela.dyn�����Ϣ
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
    //��ȡ.rela.plt�����Ϣ
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
    //�α�����PT_DYNAMIC
    auto *ehdr = (Elf64_Ehdr *) m_elfData;
    auto *phdr = (Elf64_Phdr *) (m_elfData + ehdr->e_phoff);
    auto *shdr = (Elf64_Shdr *) (m_elfData + ehdr->e_shoff);
    auto len = ehdr->e_phnum;
    printf("====================��̬��(Dynamic section)��=======================\n");
    for (int i = 0; i < len; ++i) {
        if(phdr[i].p_type == PT_DYNAMIC){
            //����
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
