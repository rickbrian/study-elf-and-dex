#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "dexFile.h"

//存储dex文件数据
char g_dexData[0x1000] ={};
//dex文件头部
DexHeader * g_header = NULL;
//数组存储字符串
char * g_stringData = NULL;
int g_strData[0x100] = {0};

// type_ids
int g_type_ids[0x100] = {0};


//函数原型
typedef struct proto_ids{
    char return_type[0x100];
    char parameters_type[0x100];
}proto_ids;
proto_ids  g_proto[0x100] = {0};

//字段
typedef struct field_ids{
    char type[0x100];
    char class[0x100];
    char name[0x100];
}field_ids;
field_ids g_field[0x100] = {0};

//方法
typedef struct method_ids{
    char return_type[0x100];
    char class[0x100];
    char name[0x100];
    char parameters_type[0x100];
}method_ids;
method_ids g_method[0x100] = {0};


char * g_type[] = {"V","Z","B","S","C","I","J","F","D"};
char * g_type2[] = {"void","boolean","byte","short","char","int","long","float","double"};
//转化
char * getType(char* ty){
    for (int i = 0; i < 9; i++) {
        if(strcmp(ty,g_type[i]) == 0){
            return g_type2[i];
        }
    }
    return NULL;
}

/**
0X1 public
0X2 private
0X4 protected
0X8 static
0x10	final
0x200  interface
0x400	abstract
0x2000 annotation
0x4000 enum
 */
char * parseFlag(int flag){
    char * str = "";
    if(flag & 0X1){
        str = "public";
    }
    if(flag & 0X2){
        str = "private";
    }
    if(flag & 0X4){
        str = "protected";
    }
    if(flag & 0X8){
        str = "static";
    }
    if(flag & 0X10){
        str = "final";
    }
    if(flag & 0x200){
        str = "interface";
    }
    if(flag & 0x400){
        str = "abstract";
    }
    if(flag & 0x2000){
        str = "annotation";
    }
    if(flag & 0x4000){
        str = "enum";
    }
    return str;
}


bool getDexDate(const char * filePath){
    FILE * file = fopen(filePath,"rb");
    if(file == NULL){
        printf("open file error\n");
        return false;
    }
    fseek(file,0,SEEK_END);
    long fileSize = ftell(file);
    fseek(file,0,SEEK_SET);
    fread(g_dexData, 1, fileSize, file);
    fclose(file);
    return true;
}

int readUnsignedLeb128(const u1** pStream) {
    const u1* ptr = *pStream;
    int result = *(ptr++);

    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *pStream = ptr;
    return result;
}

int readSignedLeb128(const u1** pStream) {
    const u1* ptr = *pStream;
    int result = *(ptr++);

    if (result <= 0x7f) {
        result = (result << 25) >> 25;
    } else {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur <= 0x7f) {
            result = (result << 18) >> 18;
        } else {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur <= 0x7f) {
                result = (result << 11) >> 11;
            } else {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur <= 0x7f) {
                    result = (result << 4) >> 4;
                } else {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *pStream = ptr;
    return result;
}



void parseHeader(){
    g_header = (DexHeader *)g_dexData;
    printf("------------------------DEX文件结构-------------------------\n");
    printf("模数:%s\n", g_header->magic);
    printf("校验和:0x%x\n", g_header->checksum);
    printf("SHA-1 签名:");
    for (int i = 0; i < kSHA1DigestLen; ++i) {
        printf("%02x", g_header->signature[i]);
    }
    printf("\n文件大小:0x%x\n", g_header->fileSize);
    printf("头部大小:0x%x\n", g_header->headerSize);
    printf("字节序标记:0x%x\n", g_header->endianTag);
    printf("链接大小:0x%x\n", g_header->linkSize);
    printf("链接偏移:0x%x\n", g_header->linkOff);
    printf("映射偏移:0x%x\n", g_header->mapOff);
    printf("字符串数量:0x%x\n", g_header->stringIdsSize);
    printf("字符串偏移:0x%x\n", g_header->stringIdsOff);
    printf("类型数量:0x%x\n", g_header->typeIdsSize);
    printf("类型偏移:0x%x\n", g_header->typeIdsOff);
    printf("原型数量:0x%x\n", g_header->protoIdsSize);
    printf("原型偏移:0x%x\n", g_header->protoIdsOff);
    printf("字段数量:0x%x\n", g_header->fieldIdsSize);
    printf("字段偏移:0x%x\n", g_header->fieldIdsOff);
    printf("方法数量:0x%x\n", g_header->methodIdsSize);
    printf("方法偏移:0x%x\n", g_header->methodIdsOff);
    printf("类定义数量:0x%x\n", g_header->classDefsSize);
    printf("类定义偏移:0x%x\n", g_header->classDefsOff);
    printf("数据大小:0x%x\n", g_header->dataSize);
    printf("数据偏移:0x%x\n", g_header->dataOff);
    printf("----------------------------------------------------------------\n");

}


void parseStringIds(){
    printf("-----------------------------字符串解析-----------------------------------\n");
    g_stringData = g_dexData + g_header->stringIdsOff;
    char *dex = g_dexData;
    char* string = g_stringData;
    for (int i = 0; i < g_header->stringIdsSize; i++) {
        u4 stringOff = *(u4 *)string;
        u1 * string_data_item = dex + stringOff;
        int offset = readUnsignedLeb128((const u1**)&string_data_item);
        char* data = (char*)string_data_item;
        printf("字符串偏移:%x size:%d %s\n",stringOff,offset,data);
        //存一下每个字符串的偏移
        g_strData[i] = data - dex;
        string += 4;
    }
}

void parseTypeIds(){
    printf("-----------------------------类型解析-----------------------------------\n");
    char * typeData = g_dexData + g_header->typeIdsOff;
    for (int i = 0; i < g_header->typeIdsSize; i++) {
        u4 typeIdx = *(u4 *)typeData;

        char *type = g_strData[typeIdx] + g_dexData;
        char *po = getType(type)  == NULL ? type : getType(type);
        printf("type_ids[%d] = %d  %s\n",i,typeIdx , po);

        //存一下类型的偏移
        g_type_ids[i] = g_strData[typeIdx];

        typeData += 4;
    }
}

void parseDexProto(){
    printf("-----------------------------原型解析-----------------------------------\n");
    char* proto = g_dexData + g_header->protoIdsOff;

    for (int i = 0; i < g_header->protoIdsSize; i++) {
        u4 shortyIdx = *(u4 *)proto; //方法原型的简称
        u4 returnTypeIdx = *(u4 *)(proto + 4); //返回类型
        u4 parametersOff = *(u4 *)(proto + 8); //参数列表偏移
        char *shorty = g_strData[shortyIdx] + g_dexData;
        char *returnType = g_type_ids[returnTypeIdx] + g_dexData;

        strcpy(g_proto[i].return_type,getType(returnType)  == NULL ? returnType : getType(returnType));

        //解析参数列表
        char sz[0x100] = {0};
        strcat(sz,"(");
        if(parametersOff != 0){
            u4 size = *(u4 *)(g_dexData + parametersOff);
            for (int j = 0; j < size; j++) {
                u2 typeIdx = *(u2 *)(g_dexData + parametersOff + 4 + j * 2);
                char * type = g_type_ids[typeIdx] + g_dexData;
                //存一下
                strcat(sz,getType(type)  == NULL ? type : getType(type));

                if(j != size - 1){
                    strcat(sz,", ");
                }
            }
        }

        strcat(sz,")");
        strcpy(g_proto[i].parameters_type,sz);

        printf("proto_ids[%d] =    %s %s\n",i,g_proto[i].return_type, g_proto[i].parameters_type);

        proto += 12;
    }
}

void parseDexField(){
    printf("-----------------------------字段解析-----------------------------------\n");
    char* field = g_dexData + g_header->fieldIdsOff;
    for (int i = 0; i < g_header->fieldIdsSize; i++) {
        u2 classIdx = *(u2 *)field;
        u2 typeIdx = *(u2 *)(field + 2);
        u4 nameIdx = *(u4 *)(field + 4);
        char *classData = g_type_ids[classIdx] + g_dexData;
        char *typeData = g_type_ids[typeIdx] + g_dexData;
        char *nameData = g_strData[nameIdx] + g_dexData;

        strcpy(g_field[i].type,getType(typeData)  == NULL ? typeData : getType(typeData));
        strcpy(g_field[i].class,classData);
        strcpy(g_field[i].name,nameData);

        printf("field_ids[%d]  %s %s->%s\n",i,g_field[i].type,g_field[i].class,g_field[i].name);
        field += 8;
    }
}

void parseDexMethod(){
    printf("-----------------------------方法解析-----------------------------------\n");
    char* method = g_dexData + g_header->methodIdsOff;
    for (int i = 0; i < g_header->methodIdsSize; i++) {
        u2 classIdx = *(u2 *)method; //类的索引
        u2 protoIdx = *(u2 *)(method + 2); //原型的索引
        u4 nameIdx = *(u4 *)(method + 4); //方法名的索引
        //类
        char *classData = g_type_ids[classIdx] + g_dexData;
        //函数名称
        char *nameData = g_strData[nameIdx] + g_dexData;


        strcpy(g_method[i].return_type,g_proto[protoIdx].return_type);
        strcpy(g_method[i].class,classData);
        strcpy(g_method[i].name,nameData);
        strcpy(g_method[i].parameters_type,g_proto[protoIdx].parameters_type);

        printf("method_ids[%d]  %s %s->%s%s\n",i,g_method[i].return_type,g_method[i].class,g_method[i].name,g_method[i].parameters_type);
        method += 8;
    }
}

//解析类接口
void parseClassInter(int off) {
    char *classData = g_dexData + off;
    u4 size = *(u4 *) classData;
    for (int i = 0; i < size; i++) {
        u2 typeIdx = *(u2 *) (classData + 4 + i * 2);
        char *type = g_type_ids[typeIdx] + g_dexData;
        printf("%s", getType(type) == NULL ? type : getType(type));
        if (i != size - 1) {
            printf(" ");
        }

    }
}

//解析异常处理
void parseTryCatch(DexCode *dexCode, int triesSize){
    if(triesSize == 0){
        return;
    }
    u2* pPadding = (char*)dexCode + sizeof(DexCode) + (dexCode->insnsSize-1) * 2 - sizeof(u2);
    u2 padding = *pPadding;
    try_item * tryItem = (char*)pPadding + 2;
    char* catch_handler = (char*)tryItem + sizeof (try_item) * triesSize;
    for (int i = 0; i < triesSize; ++i) {
        printf("\t\t\ttry的起始地址:0x%X 结束地址:0x%X \n",tryItem[i].startAddr * 2,(tryItem[i].startAddr + tryItem[i].insnCount) * 2);
        //int handlerSize = readUnsignedLeb128((const u1**)&catch_handler);
        char* handler = catch_handler + tryItem[i].handlerOff;
        int sleb128 = readSignedLeb128((const u1**)&handler);
        int size = abs(sleb128);
        if(size != 0){
            for (int j = 0; j < size; ++j) {
                int catch_id = readUnsignedLeb128((const u1**)&handler);
                int addr = readUnsignedLeb128((const u1**)&handler);
                printf("\t\t\t\t捕获异常:%s 处理异常的地址:0x%X\n",g_type_ids[catch_id] + g_dexData ,addr*2);
            }
        }
        if(sleb128 <=0 ){
            int catch_all = readUnsignedLeb128((const u1**)&handler);
            printf("\t\t\t\t.catchall {:try_0x%X .. :tryend_0x%X} :tryend_0x%X\n",tryItem[i].startAddr * 2,(tryItem[i].startAddr + tryItem[i].insnCount) * 2 ,catch_all*2);
        }

    }

}

void parseDexCode(int codeOff){
    if(codeOff == 0){
        return;
    }
    DexCode * dexCode = (DexCode *)(g_dexData + codeOff);
    printf("\t\tregistersSize:%d\n",dexCode->registersSize);
    printf("\t\tinsSize:%d\n",dexCode->insSize);
    printf("\t\toutsSize:%d\n",dexCode->outsSize);
    printf("\t\ttriesSize:%d\n",dexCode->triesSize);
    parseTryCatch(dexCode,dexCode->triesSize);
    printf("\t\tdebugInfoOff:%d\n",dexCode->debugInfoOff);
    printf("\t\tinsnsSize:%d\n",dexCode->insnsSize);
    printf("\t\tcode:");
    for (int i = 0; i < dexCode->insnsSize * 2; ++i) {
        printf("%02X ", dexCode->insns[i]);
    }
    printf("\n");
}

void parseClassData(int classDataOff){
    char *classData = g_dexData + classDataOff;
    u4 staticFieldsSize = readUnsignedLeb128((const u1**)&classData);
    u4 instanceFieldsSize = readUnsignedLeb128((const u1**)&classData);
    u4 directMethodsSize = readUnsignedLeb128((const u1**)&classData);
    u4 virtualMethodsSize = readUnsignedLeb128((const u1**)&classData);

    //静态字段
    if(staticFieldsSize != 0){
        u4 fieldIdxDiff = 0;
        printf("字段:\n");
        for (int i = 0; i < staticFieldsSize; ++i) {
             fieldIdxDiff += readUnsignedLeb128((const u1**)&classData);
            u4 accessFlags = readUnsignedLeb128((const u1**)&classData);
            printf("\t%s %s\n",parseFlag(accessFlags),g_field[fieldIdxDiff].name);
        }
    }

    //实例字段
    if(instanceFieldsSize != 0){
        u4 fieldIdxDiff = 0;
        for (int i = 0; i < instanceFieldsSize; ++i) {
            fieldIdxDiff += readUnsignedLeb128((const u1**)&classData);
            u4 accessFlags = readUnsignedLeb128((const u1**)&classData);
            printf("\t%s %s\n",parseFlag(accessFlags),g_field[fieldIdxDiff].name);

        }
    }

    //直接方法
    if(directMethodsSize != 0){
        u4 methodIdxDiff = 0;
        printf("方法:\n");
        for (int i = 0; i < directMethodsSize; ++i) {
            methodIdxDiff += readUnsignedLeb128((const u1**)&classData);
            u4 accessFlags = readUnsignedLeb128((const u1**)&classData);
            u4 codeOff = readUnsignedLeb128((const u1**)&classData);
            printf("\t%s %s %s%s\n",parseFlag(accessFlags),g_method[methodIdxDiff].return_type, g_method[methodIdxDiff].name,g_method[methodIdxDiff].parameters_type);
            parseDexCode(codeOff);
        }
    }

    //虚方法
    if (virtualMethodsSize != 0){
        u4 methodIdxDiff = 0;
        for (int i = 0; i < virtualMethodsSize; ++i) {
            methodIdxDiff += readUnsignedLeb128((const u1**)&classData);
            u4 accessFlags = readUnsignedLeb128((const u1**)&classData);
            u4 codeOff = readUnsignedLeb128((const u1**)&classData);
            printf("\t%s %s %s%s\n",parseFlag(accessFlags),g_method[methodIdxDiff].return_type, g_method[methodIdxDiff].name,g_method[methodIdxDiff].parameters_type);
            parseDexCode(codeOff);
        }
    }



}

void parseDexClass(){
    printf("-----------------------------类解析-----------------------------------\n");
    DexClassDef* classDef = (DexClassDef *) (g_dexData + g_header->classDefsOff);
    for (int i = 0; i < g_header->classDefsSize; ++i) {
        printf("\n类:%s %s\n",parseFlag(classDef->accessFlags),g_type_ids[classDef->classIdx] + g_dexData);
        printf("父类:%s\n",g_type_ids[classDef->superclassIdx] + g_dexData);
        printf("接口:%X  ",classDef->interfacesOff);
        if(classDef->interfacesOff != 0){
            parseClassInter(classDef->interfacesOff);
        }
        printf("\n源文件:%s\n",g_strData[classDef->sourceFileIdx] + g_dexData);
        printf("注解:%X\n",classDef->annotationsOff);
        printf("类数据:%X\n",classDef->classDataOff);
        parseClassData(classDef->classDataOff);
        printf("静态值:%X\n",classDef->staticValuesOff);
        classDef++;
    }

}




int main(int argc,char* argv[]){

    //读取命令行参数
//    if(argc < 2){
//        printf("usage:%s <file>\n",argv[0]);
//        return  0;
//    }
//    char * fileName = argv[1];
    //"D:\\Logan\\kerui\\06.dex\\04\\04(3)\\classes.dex"

    bool nRet =  getDexDate("D:\\\\Logan\\\\kerui\\\\06.dex\\\\04\\\\04(3)\\\\classes.dex");
    if(nRet){
        parseHeader();
        parseStringIds();
        parseTypeIds();
        parseDexProto();
        parseDexField();
        parseDexMethod();
        parseDexClass();
    }




    printf("Hello, World!\n");
    system("pause");
    return 0;
}
