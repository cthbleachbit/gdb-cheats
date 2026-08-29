from typing import List

import pytest

from gdb_cheats.assembly.types import Instruction, EncodingOptions, InstrumentBindVariable


@pytest.mark.parametrize(
    ("instruction", "expect"),
    [
        (
            Instruction(assembly="sub %r13d,%eax",
                        encoding=EncodingOptions.LOAD),
            ["    {load} sub %r13d,%eax"],
        ),
        (
            Instruction(assembly="sub %r13d,%eax"),
            ["    sub %r13d,%eax"],
        ),
        (
            Instruction(assembly="sub %r13d,%eax",
                        action=InstrumentBindVariable("$rip", "test_var")),
            [
                ".set bind_variable_test_var, .",
                "    sub %r13d,%eax",
            ],
        )
    ],
)
def test_instruction_serialize(instruction, expect: List[str]):
    assert instruction.as_gnu_assembly() == expect
