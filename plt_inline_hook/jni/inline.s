.arch armv8-a

.globl tramplo  

// tramplo:
//     ldr x16,addr_dst
//     br x16
// addr_dst:
//     .quad 0x1122112211221122


// tramplo2:
//     sub sp,sp,0x100
//     stp x0,x1,[sp]
//     stp x2,x3,[sp,0x10]
//     stp x4,x5,[sp,0x20]
//     stp x6,x7,[sp,0x30]
//     stp x8,x9,[sp,0x40]
//     stp x10,x11,[sp,0x50]
//     stp x12,x13,[sp,0x60]
//     stp x14,x15,[sp,0x70]
//     stp x16,x17,[sp,0x80]
//     stp x18,x19,[sp,0x90]
//     stp x20,x21,[sp,0xa0]
//     stp x22,x23,[sp,0xb0]
//     stp x24,x25,[sp,0xc0]
//     stp x26,x27,[sp,0xd0]
//     stp x28,x29,[sp,0xe0]
//     str x30,[sp,0xf0]


//     //调用自己的函数
//     bl myPrintf


//     ldp x0,x1,[sp]
//     ldp x2,x3,[sp,0x10]
//     ldp x4,x5,[sp,0x20]
//     ldp x6,x7,[sp,0x30]
//     ldp x8,x9,[sp,0x40]
//     ldp x10,x11,[sp,0x50]
//     ldp x12,x13,[sp,0x60]
//     ldp x14,x15,[sp,0x70]
//     ldp x16,x17,[sp,0x80]
//     ldp x18,x19,[sp,0x90]
//     ldp x20,x21,[sp,0xa0]
//     ldp x22,x23,[sp,0xb0]
//     ldp x24,x25,[sp,0xc0]
//     ldp x26,x27,[sp,0xd0]
//     ldp x28,x29,[sp,0xe0]
//     ldr x30,[sp,0xf0]
//     add sp,sp,0x100

// oldcode:
//     .word 0x11112222,0x22223333,0x33334444,0x44445555
//     ldr x16,oldaddr 
//     br x16
// oldaddr:
//     .quad 0x1122112211221122


tramplo:
    ldr x16,addr_dst
    br x16
addr_dst:
    .quad 0x1122112211221122


tramplo2:
    sub sp,sp,0x100
    stp x0,x1,[sp]
    stp x2,x3,[sp,0x10]
    stp x4,x5,[sp,0x20]
    stp x6,x7,[sp,0x30]
    stp x8,x9,[sp,0x40]
    stp x10,x11,[sp,0x50]
    stp x12,x13,[sp,0x60]
    stp x14,x15,[sp,0x70]
    stp x16,x17,[sp,0x80]
    stp x18,x19,[sp,0x90]
    stp x20,x21,[sp,0xa0]
    stp x22,x23,[sp,0xb0]
    stp x24,x25,[sp,0xc0]
    stp x26,x27,[sp,0xd0]
    stp x28,x29,[sp,0xe0]
    str x30,[sp,0xf0]


    //调用自己的函数

newfun:
    ldr x16,hookaddr
    blr x16

    ldp x0,x1,[sp]
    ldp x2,x3,[sp,0x10]
    ldp x4,x5,[sp,0x20]
    ldp x6,x7,[sp,0x30]
    ldp x8,x9,[sp,0x40]
    ldp x10,x11,[sp,0x50]
    ldp x12,x13,[sp,0x60]
    ldp x14,x15,[sp,0x70]
    ldp x16,x17,[sp,0x80]
    ldp x18,x19,[sp,0x90]
    ldp x20,x21,[sp,0xa0]
    ldp x22,x23,[sp,0xb0]
    ldp x24,x25,[sp,0xc0]
    ldp x26,x27,[sp,0xd0]
    ldp x28,x29,[sp,0xe0]
    ldr x30,[sp,0xf0]
    add sp,sp,0x100

oldcode:
    .word 0x11112222,0x22223333,0x33334444,0x44445555
    ldr x16,oldaddr 
    br x16
oldaddr:
    .quad 0x1122112211221122

hookaddr:
    .quad 0x1122112211221122