# Assembly in att syntax for GNU as

.text

# 0x0000000041928d24	41 89 84 24 24 02 00 00
    mov    %eax,0x224(%r12)
# 0x0000000041928d2c	EB 13
    jmp    skip_hp
# 0x0000000041928d2e  49 63 84 24 24 02 00 00
    movslq 0x224(%r12),%rax

# Subtracting damage points
# 0x0000000041928d36	41 2B C5
    {load} sub    %r13d,%eax

# Saving new HP to player status struct + 0x224
# 0x0000000041928d39	41 89 84 24 24 02 00 00
watchpoint:
    mov    %eax,0x224(%r12)


skip_hp:
# 0x0000000041928d41	48 8B 1C 24
    mov    (%rsp),%rbx

# 0x0000000041928d45	48 8B 6C 24 08
    mov    0x8(%rsp),%rbp

# 0x0000000041928d4a	4C 8B 64 24 10
    mov    0x10(%rsp),%r12
# 0x0000000041928d4f	4C 8B 6C 24 18
    mov    0x18(%rsp),%r13
# 0x0000000041928d54	4C 8B 7C 24 20
    mov    0x20(%rsp),%r15
# 0x0000000041928d59	48 83 C4 58
    add    $0x58,%rsp
# 0x0000000041928d5d	C3
    ret
