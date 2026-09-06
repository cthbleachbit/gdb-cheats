import pytest

from gdb_cheats.assembly.programs import assembler_native_machine
from gdb_cheats.assembly.types import Snippet


@pytest.fixture(scope="session")
def require_machine():
    assembler_arch = assembler_native_machine()

    def _require_machine(snippet: Snippet):
        if assembler_arch != snippet.machine:
            pytest.xfail(f"Skipping tests requiring {snippet.machine} on {assembler_arch}")

    return _require_machine
