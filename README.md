"# study-elf-and-dex" 
DexParse dex文件格式解析
ELF_parse elf文件格式解析
load_elf 实现手动so的加载和 myDlsym
plt_inline_hook plt 和 inline hook的简易实现
shell_elf 定制linker简单实现，替换壳程序的soinfo
shell_elf_as 安卓工程中实现linker加载so,替换壳程序的soinfo,实现动态注册native函数，java层成功调用动态加载后源so函数
so_inject 使用ptrace往目标进程中注入指定的so程序