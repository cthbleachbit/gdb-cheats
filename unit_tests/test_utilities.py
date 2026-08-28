from typing import List

import pytest

from gdb_cheats.utilities import ConstantResolver

@pytest.mark.parametrize(("constant", "includes", "expected"), [
    ("0x1234", [], 0x1234),
    ("PROT_NONE", ["sys/mman.h"], 0),
    ("MADV_GUARD_REMOVE", ["sys/mman.h"], 103),
])
def test_constant_resolver(constant: str, includes: List[str], expected: int):
    resolver = ConstantResolver()
    assert resolver.constant_resolve(constant, includes) == expected
    pass
