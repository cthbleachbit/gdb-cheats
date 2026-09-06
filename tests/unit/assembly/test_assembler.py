import copy
import sys

from gdb_cheats.assembly.assembler import *
from gdb_cheats.assembly.types import *
from .testlib import require_machine

TEST_SNIPPET = Snippet(
    "test_snippet",
    Machine.AMD64,
    [
        Instruction("mov %eax,0x224(%r12)"),
        Instruction("jmp skip_hp"),
        Instruction("movslq 0x224(%r12),%rax"),
        Instruction(
            "sub %r13d,%eax",
            label="apply_damage",
            encoding=EncodingOptions.STORE),
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
    ]
)


def test_assembler(require_machine):
    require_machine(TEST_SNIPPET)

    with NamedTemporaryFile('w+b', suffix=".o", delete_on_close=False) as f:
        f.close()
        invoke_assembler(TEST_SNIPPET.assembly_source, f.name)

        symbols = invoke_objdump_dump_symbol(f.name, TEST_SNIPPET.section_name)
        assert symbols["skip_hp"] == 0x1d
        assert symbols["apply_damage"] == 0x12
        assert symbols["bind_variable_player_base"] == 0x15

        raw_bin = invoke_objcopy_dump_section(f.name, TEST_SNIPPET.section_name)
        assert raw_bin[:10] == b'\x41\x89\x84\x24\x24\x02\x00\x00\xeb\x13'

        pass


def test_line_by_line_offset(require_machine):
    require_machine(TEST_SNIPPET)

    test_copy = copy.deepcopy(TEST_SNIPPET)

    human_readable = TEST_SNIPPET.format_side_by_side()

    assert not test_copy.is_assembled
    test_copy.assemble()
    assert test_copy.is_assembled
    assert not TEST_SNIPPET.is_assembled

    human_readable = test_copy.format_side_by_side()
    print(human_readable, file=sys.stderr)
