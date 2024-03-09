//
// Created by PC on 2024/2/29.
//

#ifndef ELF_PARSE_ELF_H
#define ELF_PARSE_ELF_H

#define parse_type(x) (x == ET_NONE ? "No file type" : \
                  x == ET_REL ? "Relocatable file" : \
                  x == ET_EXEC ? "Executable file" : \
                  x == ET_DYN ? "Shared object file" : \
                  x == ET_CORE ? "Core" : "Unknown type")


#define parse_el_class(x) (x == ELFCLASSNONE ? "Invalid class" : \
                  x == ELFCLASS32 ? "32λ" : \
                  x == ELFCLASS64 ? "64λ" : "Unknown class")

#define  parse_el_data(x) (x == ELFDATANONE ? "Invalid data encoding" : \
                  x == ELFDATA2LSB ? "С��" : \
                  x == ELFDATA2MSB ? "���" : "Unknown data encoding")



#define pare_em_machine(x) (x == EM_NONE ? "No machine" : \
                  x == EM_386 ? "x86" : \
                  x == EM_X86_64 ? "X86_64" : \
                  x == EM_ARM ? "ARM" : \
                  x == EM_AARCH64 ? "ARM64" : "Unknown machine")


#define parse_section_type(x) (x == SHT_NULL ? "NULL" : \
                  x == SHT_PROGBITS ? "�����" : \
                  x == SHT_SYMTAB ? "���Ž�" : \
                  x == SHT_STRTAB ? "�ַ�����" : \
                  x == SHT_RELA ? "�ض�λ��" : \
                  x == SHT_HASH ? "��ϣ��" : \
                  x == SHT_DYNAMIC ? "��̬��" : \
                  x == SHT_NOTE ? "��־�ļ�" : \
                  x == SHT_NOBITS ? "û���ļ�����" : \
                  x == SHT_REL ? "�ض�λ" : \
                  x == SHT_SHLIB ? "SHT_SHLIB" : \
                  x == SHT_INIT_ARRAY ? "init_array" : \
                  x == SHT_FINI_ARRAY ? "fini_array" : \
                  x == SHT_PREINIT_ARRAY ? "preinit_array" : \
                  x == SHT_GNY_versym ? "GNY versym" : \
                  x == SHT_GNU_verdneed ? "GNY verdneed" : \
                  x == SHT_GNU_HASH ? "GNY HASH" : \
                  x == SHT_DYNSYM ? "���Ž�" : " section type")


#define  parse_symbol_bind(x) (ELF_ST_BIND(x) == STB_LOCAL ? "�ֲ�" : \
                  ELF_ST_BIND(x) == STB_GLOBAL ? "ȫ��" : \
                  ELF_ST_BIND(x) == STB_WEAK ? "��" : "Unknown bind")

#define  parse_symbol_type(x) (ELF_ST_TYPE(x) == STT_NOTYPE ? "No type" : \
                  ELF_ST_TYPE(x) == STT_OBJECT ? "���ݶ���" : \
                  ELF_ST_TYPE(x) == STT_FUNC ? "����" : \
                  ELF_ST_TYPE(x) == STT_SECTION ? "��" : \
                  ELF_ST_TYPE(x) == STT_FILE ? "�ļ�" : "Unknown type")


#define parse_segment_type(x) (x == PT_NULL ? "NULL" : \
                  x == PT_LOAD ? "�ɼ���" : \
                  x == PT_DYNAMIC ? "��̬��" : \
                  x == PT_INTERP ? "������" : \
                  x == PT_NOTE ? "ע����Ϣ" : \
                  x == PT_SHLIB ? "����" : \
                  x == PT_PHDR ? "�α�����" : \
                  x == PT_TLS ? "TLS" : \
                  x == PT_GNU_EH_FRAME ? "GNU_EH_FRAME" : \
                  x == PT_GNU_STACK ? "GNU_STACK" : \
                  x == PT_GNU_RELRO ? "GNU_RELRO" : \
                  x == PT_GNU_PROPERTY ? "GNU_PROPERTY" : \
                  x == PT_AARCH64_MEMTAG_MTE ? "AARCH64_MEMTAG_MTE" : "Unknown type")


#define  R_AARCH64_GLOB_DAT 1025
#define  R_AARCH64_JUMP_SLOT 1026
#define  R_AARCH64_RELATIVE 1027

#define  parse_rela_info_type(x) (ELF64_R_TYPE(x) == R_AARCH64_GLOB_DAT ? "R_AARCH64_GLOB_DAT" : \
                  ELF64_R_TYPE(x) == R_AARCH64_JUMP_SLOT ? "R_AARCH64_JUMP_SLOT" : \
                  ELF64_R_TYPE(x) == R_AARCH64_RELATIVE ? "R_AARCH64_RELATIVE" : "other type")


#define parse_dynamic_tag(x) (x == DT_NULL ? "NULL" : \
                            x == DT_NEEDED ? "NEEDED" : \
                            x == DT_PLTRELSZ ? "PLTRELSZ" : \
                            x == DT_PLTGOT ? "PLTGOT" : \
                            x == DT_HASH ? "HASH" : \
                            x == DT_STRTAB ? "STRTAB" : \
                            x == DT_SYMTAB ? "SYMTAB" : \
                            x == DT_RELA ? "RELA" : \
                            x == DT_RELASZ ? "RELASZ" : \
                            x == DT_RELAENT ? "RELAENT" : \
                            x == DT_STRSZ ? "STRSZ" : \
                            x == DT_SYMENT ? "SYMENT" : \
                            x == DT_INIT ? "INIT" : \
                            x == DT_FINI ? "FINI" : \
                            x == DT_SONAME ? "SONAME" : \
                            x == DT_RPATH ? "RPATH" : \
                            x == DT_SYMBOLIC ? "SYMBOLIC" : \
                            x == DT_REL ? "REL" : \
                            x == DT_RELSZ ? "RELSZ" : \
                            x == DT_RELENT ? "RELENT" : \
                            x == DT_PLTREL ? "PLTREL" : \
                            x == DT_DEBUG ? "DEBUG" : \
                            x == DT_TEXTREL ? "TEXTREL" : \
                            x == DT_JMPREL ? "JMPREL" : \
                            x == DT_BIND_NOW ? "BIND_NOW" : \
                            x == DT_INIT_ARRAY ? "INIT_ARRAY" : \
                            x == DT_FINI_ARRAY ? "FINI_ARRAY" : \
                            x == DT_INIT_ARRAYSZ ? "INIT_ARRAYSZ" : \
                            x == DT_FINI_ARRAYSZ ? "FINI_ARRAYSZ" : \
                            x == DT_RUNPATH ? "RUNPATH" : \
                            x == DT_FLAGS ? "FLAGS" : \
                            x == DT_ENCODING ? "ENCODING" : \
                            x == DT_PREINIT_ARRAY ? "PREINIT_ARRAY" : \
                            x == DT_PREINIT_ARRAYSZ ? "PREINIT_ARRAYSZ" : \
                            x == DT_MAXPOSTAGS ? "MAXPOSTAGS" : \
                            x == DT_LOOS ? "LOOS" : \
                            x == DT_SUNW_AUXILIARY ? "SUNW_AUXILIARY" : \
                            x == DT_SUNW_RTLDINF ? "SUNW_RTLDINF" : \
                            x == DT_SUNW_FILTER ? "SUNW_FILTER" : \
                            x == DT_SUNW_CAP ? "SUNW_CAP" : \
                            x == DT_SUNW_SYMTAB ? "SUNW_SYMTAB" : \
                            x == DT_SUNW_SYMSZ ? "SUNW_SYMSZ" : \
                            x == DT_SUNW_ENCODING ? "SUNW_ENCODING" : \
                            x == DT_SUNW_SORTENT ? "SUNW_SORTENT" : \
                            x == DT_SUNW_SYMSORT ? "SUNW_SYMSORT" : \
                            x == DT_SUNW_SYMSORTSZ ? "SUNW_SYMSORTSZ" : \
                            x == DT_SUNW_TLSSORT ? "SUNW_TLSSORT" : \
                            x == DT_SUNW_TLSSORTSZ ? "SUNW_TLSSORTSZ" : \
                            x == DT_SUNW_CAPINFO ? "SUNW_CAPINFO" : \
                            x == DT_SUNW_STRPAD ? "SUNW_STRPAD" : \
                            x == DT_SUNW_CAPCHAIN ? "SUNW_CAPCHAIN" : \
                            x == DT_SUNW_LDMACH ? "SUNW_LDMACH" : \
                            x == DT_SUNW_CAPCHAINENT ? "SUNW_CAPCHAINENT" : \
                            x == DT_SUNW_CAPCHAINSZ ? "SUNW_CAPCHAINSZ" : \
                            x == DT_HIOS ? "HIOS" : \
                            x == DT_VALRNGLO ? "VALRNGLO" : \
                            x == DT_CHECKSUM ? "CHECKSUM" : \
                            x == DT_PLTPADSZ ? "PLTPADSZ" : \
                            x == DT_MOVEENT ? "MOVEENT" : \
                            x == DT_MOVESZ ? "MOVESZ" : \
                            x == DT_POSFLAG_1 ? "POSFLAG_1" : \
                            x == DT_SYMINSZ ? "SYMINSZ" : \
                            x == DT_SYMINENT ? "SYMINENT" : \
                            x == DT_VALRNGHI ? "VALRNGHI" : \
                            x == DT_ADDRRNGLO ? "ADDRRNGLO" : \
                            x == DT_CONFIG ? "CONFIG" : \
                            x == DT_DEPAUDIT ? "DEPAUDIT" : \
                            x == DT_AUDIT ? "AUDIT" : \
                            x == DT_PLTPAD ? "PLTPAD" : \
                            x == DT_MOVETAB ? "MOVETAB" : \
                            x == DT_SYMINFO ? "SYMINFO" : \
                            x == DT_ADDRRNGHI ? "ADDRRNGHI" : \
                            x == DT_RELACOUNT ? "RELACOUNT" : \
                            x == DT_RELCOUNT ? "RELCOUNT" : \
                            x == DT_FLAGS_1 ? "FLAGS_1" : \
                            x == DT_VERDEF ? "VERDEF" : \
                            x == DT_VERDEFNUM ? "VERDEFNUM" : \
                            x == DT_VERNEED ? "VERNEED" : \
                            x == DT_VERNEEDNUM ? "VERNEEDNUM" : \
                            x == DT_LOPROC ? "LOPROC" : \
                            x == DT_SPARC_REGISTER ? "SPARC_REGISTER" : \
                            x == DT_AUXILIARY ? "AUXILIARY" : \
                            x == DT_USED ? "USED" : \
                            x == DT_GNU_HASH ? "GNU_HASH" : \
                            x == DT_VERSYM ? "VERSYM" : \
                            x == DT_FILTER ? "FILTER" : "UNKNOWN")


//����ELF�ļ�����
class ELF {


public:
    char* m_elfData = nullptr;

public:
    //���캯��
    ELF(const char *file_path);
    //��������
    ~ELF();
    //��ȡELF�ļ���ͷ����Ϣ
    void get_elf_header() const;

    //��ȡELF�ļ��Ľڱ���Ϣ
    void get_section_header() const;


    //��ȡELF�ļ��ķ��ű���Ϣ
    int get_str_index( const char *name ) const;

    void get_symbol_table() const;

    void get_dynamic_symbol_table() const;


    //�����α�
    void get_program_header() const;

    //�����α�ע�ͽ�
    void get_program_note()const;

    //�ض�λ��
    void get_rela_dyn()const;
    void get_rela_plt()const;


    //������̬�� -- Dynamic section
    void get_dynamic_section()const;


};


#endif //ELF_PARSE_ELF_H
