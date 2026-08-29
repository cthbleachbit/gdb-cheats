from gdb_cheats.assembly.types import *

SNIPPET_HP_TAKE_DAMAGE = Snippet(
    "hp_take_damage",
    [
        Instruction("mov %eax,0x224(%r12)"),
        Instruction("jmp skip_hp"),
        Instruction("movslq 0x224(%r12),%rax"),
        Instruction(
            "sub %r13d,%eax",
            label="apply_damage",
            encoding=EncodingOptions.LOAD),
        Instruction(
            "mov %eax,0x224(%r12)",
            label="save_damage",
            action=InstrumentBindVariable(
                expression="$r12",
                variable_name="player_base"
            )
        ),
        Instruction(
            "mov (%rsp),%rbx",
            label="skip_hp"
        ),
        Instruction("mov 0x8(%rsp),%rbp"),
        Instruction("mov 0x10(%rsp),%r12"),
        Instruction("mov 0x18(%rsp),%r13"),
        Instruction("mov 0x20(%rsp),%r15"),
        Instruction("add $0x58,%rsp"),
        Instruction("ret"),
    ]
)
