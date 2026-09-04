"""Routines to assemble instructions with GNU assembler"""
import logging
import subprocess
from tempfile import NamedTemporaryFile
from typing import Dict

from gdb_cheats.assembly.programs import *

_logger = logging.getLogger(__name__)


def invoke_assembler(source: str, output_file: str):
    """Assemble the given source code into an object file using GNU assembler"""

    with NamedTemporaryFile("w", suffix=".S", delete_on_close=False) as asm_source:
        asm_source.write(source)
        asm_source.flush()
        asm_source.close()

        _logger.debug("Written assembly source %s", asm_source.name)

        assembler_cmd = [
            get_gnu_assembler(), "-o", output_file, asm_source.name
        ]

        assembler_proc = subprocess.run(assembler_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, encoding="utf-8", env=get_tooling_environ())

        if assembler_proc.returncode != 0:
            raise RuntimeError(f"GNU assembler failed: {assembler_proc.stderr}")

        _logger.debug("Written object file %s", output_file)


def invoke_objdump_dump_symbol(elf_file: str, section_name: str) -> Dict[str, int]:
    """
    Dump symbols of the given ELF file using GNU objdump in the given section.
    """

    objdump_cmd = [
        get_objdump(), "--wide", "--syms", "--section", section_name, elf_file
    ]

    objdump_proc = subprocess.run(objdump_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, encoding="utf-8", env=get_tooling_environ())

    if objdump_proc.returncode != 0:
        raise RuntimeError(f"GNU objdump failed: {objdump_proc.stderr}")

    # Parse output
    lines = [l.strip() for l in objdump_proc.stdout.splitlines() if l.strip()]

    line_sym_table_start = lines.index("SYMBOL TABLE:")
    lines = lines[line_sym_table_start + 1:]

    symbols = {}
    for line in lines:
        # Line in the format of
        # `offset_in_section flag section_name value symbol_name`
        fields = line.split()
        flag = fields[1]
        if flag != "l":
            continue
        offset = int(fields[0], 16)
        symbol_name = fields[4]
        symbols[symbol_name] = offset

    return symbols


def invoke_objcopy_dump_section(elf_file: str, section_name: str) -> bytes:
    """
    Dump raw binary contents in the given section from the given ELF.
    """

    with NamedTemporaryFile("w+", suffix=".bin", delete_on_close=False) as raw_binary:
        raw_binary.close()

        objcopy_cmd = [
            get_objcopy(), "--dump-section", f"{section_name}={raw_binary.name}", elf_file
        ]

        objcopy_proc = subprocess.run(objcopy_cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, encoding="utf-8", env=get_tooling_environ())

        if objcopy_proc.returncode != 0:
            raise RuntimeError(f"GNU objcopy failed: {objcopy_proc.stderr}")

        with open(raw_binary.name, "rb") as f:
            return f.read()
