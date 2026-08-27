# SPDX-License-Identifier: GPL-3.0

"""
Utilities that do not interface with gdb.
"""

import logging
import subprocess
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, TypeAlias, Union, Callable

_logger = logging.getLogger(__name__)

Address: TypeAlias = int
Offset: TypeAlias = int
Numeric: TypeAlias = Union[int, float]
Buffer: TypeAlias = Union[bytes, memoryview]

ValuePredicate: TypeAlias = Callable[[Buffer], bool]
AddressPredicate: TypeAlias = Callable[[Address], bool]


class ConstantResolver:
    """
    Constant resolver - shorthands to get numeric constants in C code.
    """

    def __init__(self):
        self._constants: Dict[str, Optional[int]] = dict()

    @classmethod
    def compile_and_run(cls, source: List[str]) -> Optional[int]:
        """
        Compile and run the given source code.

        May raise
        """

        test_source = "".join([line + "\n" for line in source])

        with NamedTemporaryFile("r+", suffix=".elf", delete_on_close=False) as test_elf:
            test_elf.close()
            gcc_process = subprocess.Popen(
                ["gcc", "-x", "c", "-", "-o", test_elf.name],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )
            try:
                gcc_stdout, gcc_stderr = gcc_process.communicate(test_source, timeout=10)
            except subprocess.TimeoutExpired:
                _logger.error(f"Compilation of constant resolve code timed out.")
                return None
            if gcc_process.returncode != 0:
                raise EnvironmentError(f"Failed to compile constant resolve code:\n{gcc_stderr}")

            test_process = subprocess.run([test_elf.name], check=True, stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, encoding="utf-8")

            resolved_constant = int(test_process.stdout.strip())

        return resolved_constant

    def constant_resolve(self, name: str, includes: Optional[List[str]] = None) -> Optional[int]:
        """
        Invokes compiler to resolve a preprocessor-defined constant.
        """

        if name in self._constants.keys():
            return self._constants[name]

        if includes is None:
            includes = []

        lines = ["#include <stdio.h>"]
        lines.extend([f"#include <{header}>" for header in includes])
        lines.append("int main() { printf(\"%d\\n\", " + name + "); }")

        resolved_constant = self.compile_and_run(lines)

        self._constants[name] = resolved_constant

        return resolved_constant
