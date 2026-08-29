# Hollow Knight Silksong

The game seems to always allocate runtime player data aligned to 4K boundaries. Fields are at fixed offsets relative to
this player data base pointer.

Note: At the time of writing the following observation is on game version 1.0.30000

## From player status base 0x00007f50cb624000

HP: +0x224

### Locating the player status base address

Taking damage:

```
; 0x0000000041928d24	41 89 84 24 24 02 00 00
    mov dword ptr [r12 + 0x224], eax
; 0x0000000041928d2c	EB 13
    jmp 0x41928d41
; 0x0000000041928d2e  49 63 84 24 24 02 00 00
    movsxd rax, dword ptr [r12 + 0x224]
    
; Subtracting damage points
; 0x0000000041928d36	41 2B C5	
    sub eax, r13d

; Saving new HP to player status struct + 0x224
; 0x0000000041928d39	41 89 84 24 24 02 00 00
    mov dword ptr [r12 + 0x224], eax

; Watch point fires here.
; 0x0000000041928d41	48 8B 1C 24
    mov rbx, qword ptr [rsp]
; 0x0000000041928d45	48 8B 6C 24 08
    mov rbp, qword ptr [rsp + 8]
; 0x0000000041928d4a	4C 8B 64 24 10
    mov r12, qword ptr [rsp + 0x10]
; 0x0000000041928d4f	4C 8B 6C 24 18
    mov r13, qword ptr [rsp + 0x18]
; 0x0000000041928d54	4C 8B 7C 24 20
    mov r15, qword ptr [rsp + 0x20]
; 0x0000000041928d59	48 83 C4 58
    add rsp, 0x58
```

Restoring health (on a bench)

```
0x00000000417ec4b5	38 02
    cmp byte ptr [rdx], al
0x00000000417ec4b7	00 00
    add byte ptr [rax], al
0x00000000417ec4b9	49 8B FF
    mov rdi, r15
0x00000000417ec4bc	66 66 90
    nop

# Get rest-at-bench HP
0x00000000417ec4bf	E8 2C 00 00 00
    call 0x417ec4f0

# Saving new HP to player status struct + 0x224
0x00000000417ec4c4	41 89 87 24 02 00 00
    mov dword ptr [r15 + 0x224], eax
    
0x00000000417ec4cb	4C 8B 3C 24
    mov r15, qword ptr [rsp]
0x00000000417ec4cf	48 83 C4 08
    add rsp, 8
0x00000000417ec4d3	C3
    ret
```

Consuming silk (needolin)

```
0x00000000417ec4b5	49 63 86 48 02 00 00
    movsxd rax, dword ptr [r14 + 0x248]
0x00000000417ec4bc  2B 44 24 08
    sub eax, dword ptr [rsp + 8]
0x00000000417ec4c0	33 C9
    xor ecx, ecx
0x00000000417ec4c2	3B C1
    cmp eax, ecx
0x00000000417ec4c4	0F 4C C1
    cmovl eax, ecx
    
# Saves modified silk level
0x00000000417ec4c7	41 89 86 48 02 00 00
    mov dword ptr [r14 + 0x248], eax
    
0x00000000417ec4ce	4C 8B 34 24
    mov r14, qword ptr [rsp]
0x00000000417ec4d2	48 83 C4 18
    add rsp, 0x18
0x00000000417ec4d6	C3
    ret
```

Recovering silk

```
0x00000000417ec4b5	4C 89 7C 24 08
    mov qword ptr [rsp + 8], r15
0x00000000417ec4ba	4C 8B F7
    mov r14, rdi
0x00000000417ec4bd	4C 8B FE
    mov r15, rsi
0x00000000417ec4c0	49 63 86 48 02 00 00
    movsxd rax, dword ptr [r14 + 0x248]
0x00000000417ec4c7	89 44 24 10
    mov dword ptr [rsp + 0x10], eax
0x00000000417ec4cb	49 63 86 48 02 00 00
    movsxd rax, dword ptr [r14 + 0x248]
    
# Charge silk
0x00000000417ec4d2	41 03 C7
    add eax, r15d
    
# Write silk to player status struct
0x00000000417ec4d5	41 89 86 48 02 00 00
    mov dword ptr [r14 + 0x248], eax
```

## From inventory base 0x00007f50cb7bb000

000-01f: potentially a header 020-???: item entries? every item seems to take 24 bytes except for flea brew and plasmium
phial

The item slots seems to be allocated in the order the player received them in the game, and consequently not portable
across save files.

### Inside every 24B item entry:

000-007: Some pointer 008-00b: Fixed number 0x10001 / 65537 00c-00f: Item count as u32 010-014: Unknown number 015-018:
0xffffffff / -1

offset below is offset of item count u32

off + pointer at 0-7 + mapped item 0ac - 0x00007f32539a50f0 - sting shard 10c - 0x00007f32539b1f90 - longpin 124 -
0x00007f32539b1f30 - flintslate 13c - 0x00007f32539b1ed0 - curveclaw 19c - 0x00007f32539b1de0 - straight pin

2a4 - 0x00007f32539b19f0 - cogwork wheel 304 - 0x00007f325398c0c0 - plasmium phial 37c - 0x00007f32539b16f0 - delver's
drill 3c4 - 0x00007f32539b7e40 - cogfly 424 - 0x00007f32539b7c80 - silkshot 454 - 0x00007f32539b8dc0 - tacks 46c -
0x00007f32539b1420 - conchcutter 484 - 0x00007f32539b13c0 - throwing ring 4cc - 0x00007f32539b7a80 - rosary cannon 55c -
0x00007f3232750720 - threefold pin 574 - 0x00007f3232750810 - pimpillo 58c - 0x00007f3232875b00 - curvesickle

### Exceptions - items with reserve

000-007: Some pointer A 008-00b: Fixed number 0x10001 / 65537 00c-00f: Item count as u32 010-014: Unknown number X
015-018: 0x10 <- Others have -1

1b4 - 0x00007f32539b1d80 - 7bea7f88 - flea brew

### Reserves section?

0x00007f50cb7dad50 - flea brew reserves 0x00007f50cb7dad68 - plasmium phial reserves

## From item base

0x00007f50cb855558 - pointer to item base = 0x00007f50cb85d000

0x00007f50cb85d050 - frayed rosary string +2 0x00007f50cb85d0b0 - craftmetal +5 0x00007f50cb85d0d0 - shard bundle +6
0x00007f50cb85d0f0 - rosary necklace +7 0x00007f50cb85d110 - rosary string +8 0x00007f50cb85d1d0 - memory locket +13
0x00007f50cb85d210 - beast shard +16 0x00007f50cb85d290 - heavy rosary necklace + 20 0x00007f50cb85d2f0 - silkeater +23
0x00007f50cb85d3f0 - hornet statuette +31 0x00007f50cb85d5b0 - seeker's soul 0x00007f50cb85d690 - pale rosary necklace
0x00007f50cb85d730 - hermit's soul
