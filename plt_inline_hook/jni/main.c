#include <stdio.h>
#include <dlfcn.h>

extern  void installInlineHook();

int main() {


    for (size_t i = 0; i < 10; i++)
    {
        printf("%zu\n",i);
    }

     FILE *file;
    file = fopen("example.txt", "r"); 
     if (file == NULL) {
        printf("无法打开文件\n");
    } 
    

    return 0;
}
