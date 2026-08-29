from tempfile import NamedTemporaryFile

from gdb_cheats.assembly.assembler import *
from gdb_cheats.contrib.hollow_knight_silksong import SNIPPET_HP_TAKE_DAMAGE


def test_assembler():
    with NamedTemporaryFile('w+b', suffix=".o", delete_on_close=False) as f:
        f.close()
        invoke_assembler(SNIPPET_HP_TAKE_DAMAGE.assembly_source, f.name)

        symbols = invoke_objdump_dump_symbol(f.name, SNIPPET_HP_TAKE_DAMAGE.section_name)
        assert len(symbols) == 4
        assert symbols["skip_hp"] == 0x1d
        assert symbols["apply_damage"] == 0x12
        assert symbols["bind_variable_player_base"] == 0x15

        raw_bin = invoke_objcopy_dump_section(f.name, SNIPPET_HP_TAKE_DAMAGE.section_name)
        assert len(raw_bin) == 0x3a
        assert raw_bin[:10] == b'\x41\x89\x84\x24\x24\x02\x00\x00\xeb\x13'

        pass
