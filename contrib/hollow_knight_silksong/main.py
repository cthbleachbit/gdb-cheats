"""
Silksong specific cheats entrypoint

Usage:
- Attach to silksong process via `cheats-gdb`
- Source this script.
- In gdb do `python silksong_start_instrumentation()`.
- In gdb do `continue`.
    - Load save file if not loaded, take some damage.
    - Should see logs about `bind_variable_player_base` firing.
- Go back to gdb and press C-c.
- Do `python silksong_begin_cheat()`.
- Profit.
"""
from gdb_cheats.assembly.instrumentation import CodeSearch
from gdb_cheats.assembly.types import *
from gdb_cheats.command import get_session
from gdb_cheats.core import VariableDefinition, ValueType

_code_search = CodeSearch()

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


def silksong_start_instrumentation():
    global _code_search
    _code_search.search_code(SNIPPET_HP_TAKE_DAMAGE)
    _code_search.enable_instrumentation(SNIPPET_HP_TAKE_DAMAGE)


def silksong_stop_instrumentation():
    global _code_search
    _code_search.disable_instrumentation(SNIPPET_HP_TAKE_DAMAGE)


def silksong_search_vars():
    global _code_search
    for key, value in _code_search.state().items():
        print(f"{key}: {value}")


def silksong_begin_cheat():
    global _code_search
    if "player_base" not in _code_search.state().keys():
        print("Player base not found")
        return

    silksong_stop_instrumentation()

    player_base = int(_code_search.state()["player_base"])
    hp_addr = player_base + 0x224
    silk_addr = player_base + 0x248

    session = get_session()
    hp_var = VariableDefinition("hp", ValueType.U32, hp_addr)
    silk_var = VariableDefinition("silk", ValueType.U32, silk_addr)
    session.variables.append(hp_var)
    session.variables.append(silk_var)
    session.variable_lock_create(hp_var, 9)
    session.variable_lock_create(silk_var, 10)


if __name__ == "__main__":
    silksong_start_instrumentation()
