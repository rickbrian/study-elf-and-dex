//
// Created by PC on 2024/2/29.
//
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/user.h>
#include <cstdlib>
#include <dirent.h>
#include <errno.h>
#include <sys/uio.h>
#include <linux/elf.h>


#define CHECK_RET(x, y, z, m) \
    do { \
        if ((x) == (y)) { \
            printf("%s failed:%s\n", z, strerror(errno)); \
            return m; \
        } else { \
            printf("%s success\n", z); \
        } \
    } while(0)


//获取寄存器
int ptrace_get_regs(pid_t pid, user_regs_struct* regs){
    iovec iov = {0};
    iov.iov_base = regs;//arm64环境下用这个
    iov.iov_len = sizeof (struct user_regs_struct );

    int ret = ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);

    return ret;
}

//设置寄存器
int ptrace_set_regs(pid_t pid, user_regs_struct* regs){
    iovec iov = {0};
    iov.iov_base = regs;//arm64环境下用这个
    iov.iov_len = sizeof (struct user_regs_struct );

    int ret = ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);

    return ret;
}


//显示寄存器
void show_reg(user_regs_struct* regs){
    for (int i = 0; i < 31; ++i) {
        if(i == 30){
            printf("LR = 0x%lx    ",  regs->regs[i]);
        }
        printf("R%d = 0x%lx    ", i, regs->regs[i]);
        if((i + 1) %8 == 0){
            printf("\n");
        }
    }
    printf("PC = 0x%lx    ", regs->pc);
    printf("SP = 0x%lx    ",  regs->sp);
    printf("state = 0x%lx\n",  regs->pstate);
}

//获取模块基址
void* get_module_base(pid_t pid , const char* name){
    char buf[20] ={};
    if(pid == -1){
        sprintf(buf, "/proc/self/maps");
    }
    else{
        sprintf(buf, "/proc/%d/maps", pid);
    }
    FILE* fp = fopen(buf, "r");
    if(fp == NULL){
        return NULL;
    }
    while (!feof(fp)){
        char line[1024] = {};
        if(fgets(line, sizeof(line), fp) == NULL){
            break;
        }
        if(strstr(line, name)){
            char* p = strtok(line, "-");
            return (void*)strtoul(p, NULL, 16);
        }
    }
    return NULL;
}

//通过遍历/proc/pid/cmdline == name , 获取pid
pid_t get_pid_by_name(const char* name){
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    pid_t  pid = -1;

    if ((dir = opendir("/proc")) == NULL) {
        perror("opendir failed");
        return pid;
    }

    while ((entry = readdir(dir)) != NULL){
        if(entry->d_type == DT_DIR){
            pid = atoi(entry->d_name);
            if(pid != 0){
                char cmdline[1024] = {};
                sprintf(cmdline, "/proc/%d/cmdline", pid);
                FILE* fp = fopen(cmdline, "r");
                if(fp){
                    char name_buf[1024] = {};
                    fgets(name_buf, sizeof(name_buf), fp);
                    if(strcmp(name, name_buf) == 0){
                        fclose(fp);
                        break;
                    }
                    fclose(fp);
                }
            }
        }
    }

    return  pid;

}

//调用函数
//pfn:要调用的函数地址
//pArgs:参数数组
//nCnt:参数个数
//nRetAddr:返回值
int ptrace_callfun(pid_t  pid,void* pfn,uint64_t* pArgs, size_t nCnt,uint64_t* nRetAddr){
    //1.获取目标进程中的函数地址

    //a.计算偏移
    Dl_info info = {0};
    int nRet = dladdr(pfn, &info);
    CHECK_RET(nRet, 0, "dladdr",-1);

    printf("dladdr base:%p name:%s  addr:%p fun name:%s\n", info.dli_fbase, info.dli_fname,info.dli_saddr, info.dli_sname);
    uint64_t  nOff = (uint8_t*)info.dli_saddr - (uint8_t*)info.dli_fbase;

    //b.获取目标进程的目标函数
    void* remote_base = get_module_base(pid, info.dli_fname);
    void* remote_pfn = (uint8_t*)remote_base + nOff;
    printf("remote_base = %p remote_pfn = %p\n",remote_base, remote_pfn);

    //1/保存寄存器环境
    user_regs_struct old_regs = {0};
    nRet = ptrace_get_regs(pid, &old_regs);
    CHECK_RET(nRet, -1, "ptrace get regs ",-1);
    //puts("old regs:");
    //show_reg(&old_regs);

    //2.修改寄存器 x30=0 pc = remote_pfn
    user_regs_struct new_regs = old_regs;
    new_regs.pc = (uint64_t)remote_pfn;
    new_regs.regs[30] = 0;
    for (int i = 0; i < nCnt; ++i) {
        new_regs.regs[i] = pArgs[i];
    }
    nRet = ptrace_set_regs(pid, &new_regs);
    CHECK_RET(nRet, -1, "ptrace set regs ",-1);

    //检查一下是否修改
    user_regs_struct test = {0};
    nRet = ptrace_get_regs(pid, &test);
    //show_reg(&test);

    //继续运行
    nRet = ptrace(PTRACE_CONT, pid, NULL, NULL);
    CHECK_RET(nRet, -1, "ptrace cont ",-1);
    //等待信号
    waitpid(pid, NULL, WUNTRACED);

    //获取返回值
    user_regs_struct ret_regs = {0};
    nRet = ptrace_get_regs(pid, &ret_regs);
    CHECK_RET(nRet, -1, "ptrace get ret regs ",-1);
    *nRetAddr = ret_regs.regs[0];

    //恢复寄存器
    nRet = ptrace_set_regs(pid, &old_regs);
    CHECK_RET(nRet, -1, "ptrace set old regs ",-1);

    return 0;
}

//远程读内存
//pRemoteAddr:远程进程地址
//pBuf:本地缓冲区
//nSize:写入大小
int ptrace_read_remote_mem(pid_t pid,void* pRemoteAddr,uint8_t* pBuf ,size_t nSize){
    int count = nSize/4;
    int* path_point = (int*)pBuf;
    int* so_path_addr =  (int*)pRemoteAddr;
    for (int i = 0; i < count; ++i) {
        *path_point = (int)(ptrace(PTRACE_PEEKDATA, pid, (void *) so_path_addr, NULL));
        path_point++;
        so_path_addr ++;
    }
    return 0;
}

//远程写内存
//pRemoteAddr:远程进程地址
//pBuf:本地缓冲区
//nSize:写入大小
int ptrace_write_remote_mem(pid_t pid,void* pRemoteAddr,uint8_t* pBuf ,size_t nSize){
    int count = nSize/4;
    int* so_path_addr = (int*)pRemoteAddr;
    int *path_point = (int*) pBuf;
    for (int i = 0; i < count; ++i) {
        int nRet = ptrace(PTRACE_POKEDATA, pid, (void*)so_path_addr, *path_point);
        //CHECK_RET(nRet, -1, "ptrace poke data",0);
        so_path_addr ++;
        path_point++;
    }
    return 0;
}

//远程读内存
//pRemoteAddr:远程进程地址
//pBuf:本地缓冲区
//nSize:写入大小
int ptrace_read_remote_mem1(pid_t pid,void* pRemoteAddr,uint8_t* pBuf ,size_t nSize){
    struct iovec local_iov = {0};
    local_iov.iov_base = pBuf;
    local_iov.iov_len = nSize;

    struct iovec remote_iov = {0};
    remote_iov.iov_base = pRemoteAddr;
    remote_iov.iov_len = nSize;

    size_t nRet = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    CHECK_RET(nRet, -1, "process_vm_readv",-1);
    return 0;
}

//远程写内存
//pRemoteAddr:远程进程地址
//pBuf:本地缓冲区
int ptrace_write_remote_mem1(pid_t pid,void* pRemoteAddr,uint8_t* pBuf ,size_t nSize){
    struct iovec local_iov = {0};
    local_iov.iov_base = pBuf;
    local_iov.iov_len = nSize;

    struct iovec remote_iov = {0};
    remote_iov.iov_base = pRemoteAddr;
    remote_iov.iov_len = nSize;

    size_t nRet = process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0);
    CHECK_RET(nRet, -1, "process_vm_writev",-1);
    return 0;
}

int move_hookso_dataapp(char *szSoPath,char *szProcessName){
    //把so放到这个路径下面data/app/com.org.shell_elf*/lib/arm64-v8a/libhook.so

    //1.获取app的路径
    DIR *dir = NULL;
    struct dirent *entry = NULL;

    if ((dir = opendir("/data/app")) == NULL) {
        perror("opendir failed");
        return -1;
    }

    char szAppPath[0x100] = {};
    while ((entry = readdir(dir)) != NULL){
        if(entry->d_type == DT_DIR){
            if(strstr(entry->d_name, szProcessName)){
                sprintf(szAppPath, "/data/app/%s", entry->d_name);
                break;
            }
        }
    }

    //拼接路径
    strcat(szAppPath, "/lib/arm64/");
    strcat(szAppPath, szSoPath);
    printf("app path:%s\n", szAppPath);

    //2.把so拷贝到这个路径下
    char szCmd[0x100] = {};
    sprintf(szCmd, "cp %s %s", szSoPath, szAppPath);
    int nRet = system(szCmd);
    CHECK_RET(nRet, -1, "system",0);

    return 0;

}


//inject libhook.so com.org.shell_elf
int main(int argc, char* argv[]) {

    if(argc < 2){
        printf("usage: %s  <libhook.so>  <process name>\n", argv[0]);
        return -1;
    }

    char szSoPath[0x100] = {};
    strcpy(szSoPath, argv[1]);

    char szProcessName[0x100] = {};
    strcpy(szProcessName, argv[2]);


    pid_t pid = get_pid_by_name(szProcessName);
    CHECK_RET(pid, 0, "get pid",0);
    printf("pid = %d\n", pid);

    int nRet = move_hookso_dataapp(szSoPath, szProcessName);
    CHECK_RET(nRet, -1, "move so",0);


    //附加进程
    long ret = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    CHECK_RET(ret, -1, "ptrace attach",0);

    //等待信号
    int nStatus = 0;
    nRet = waitpid(pid,&nStatus, WUNTRACED);
    CHECK_RET(nRet, -1, "wait",0);
    printf("wait sig:%s isstopped:%d\n", strsignal(WSTOPSIG(nStatus)) , WIFSTOPPED(nStatus));
    getchar();


    //调用函数
    uint64_t bufArgsMap[] ={0,0x1000,PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS , static_cast<uint64_t>(-1), 0};
    uint64_t nResult = 0;
    nRet = ptrace_callfun( pid,(void*)mmap64,bufArgsMap,sizeof (bufArgsMap)/sizeof (bufArgsMap[0]),&nResult);
    CHECK_RET(nRet,-1,"ptrace_callfun",0);
    printf("mmap64 result = %lx\n", nResult);

    //把so的路径写进去
    char so_path[0x100] = "libhook.so";
    ptrace_write_remote_mem1(pid, (void*)nResult, (uint8_t*)so_path, sizeof (so_path));

    //看一下so路径写进去没有
    char so_path_read[0x100] = {};
    ptrace_read_remote_mem1(pid, (void*)nResult, (uint8_t*)so_path_read, sizeof (so_path_read));
    printf("so path read:%s\n", so_path_read);

    //调用dlopen
    uint64_t bufArgsDlopen[] ={nResult, RTLD_NOW };
    nRet = ptrace_callfun(pid, (void*)(dlopen), bufArgsDlopen, sizeof (bufArgsDlopen) / sizeof (bufArgsDlopen[0]), &nResult);
    CHECK_RET(nRet,-1,"ptrace_callfun dlopen",0);
    printf("dlopen result = %lx\n", nResult);

    //检查dlerror,获取错误
    if(nResult == 0){
        nRet = ptrace_callfun(pid, (void*)(dlerror), NULL, 0, &nResult);
        CHECK_RET(nRet,-1,"ptrace_callfun dlerror",0);
        char szError[0x100] = {};
        nRet = ptrace_read_remote_mem1(pid, (void*)nResult, (uint8_t*)szError, sizeof (szError));
        CHECK_RET(nRet,-1,"read szError",0);
        printf("dlopen error:%s\n", szError);
    }

    //取消附加
    nRet = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    CHECK_RET(nRet, -1, "ptrace detach",0);


    return 0;
}