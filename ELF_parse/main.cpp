#include <iostream>
#include <stdio.h>
#include <cstdint>

#include "ELF.h"

uint32_t gnu_hash(const char* name) {
    uint32_t h = 5381;
    while (*name != 0) {
        h += (h << 5) + *name++; // h*33 + c = h + h * 32 + c = h + h << 5 + c
    }

    return h;
}




int main() {

//    while (1) {
//        char sz[0x100] = {0};
//        scanf("%s", &sz);
//        printf("hash:0x%X\n", gnu_hash(sz));
//    }


    ELF elf("libfoo.so");
    elf.get_elf_header();
    elf.get_section_header();
    elf.get_symbol_table();
    elf.get_dynamic_symbol_table();
    elf.get_program_header();
    elf.get_program_note();
    elf.get_rela_dyn();
    elf.get_rela_plt();
    elf.get_dynamic_section();


}
