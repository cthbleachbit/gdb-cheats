"""
External programs used during assembly / disassembly.
"""
import os
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Dict

_programs_searched: Dict[str, bool] = defaultdict(bool)
_programs_path: Dict[str, str] = defaultdict(str)


def _get_program(name: str, override_env_var: str, required: bool) -> str:
    """
    Look for the given program in the system path and cache the result.
    """

    global _programs_path
    global _programs_searched

    if not _programs_searched[name]:
        if override_env_var and override_env_var in os.environ.keys():
            found_program_name = os.environ.get(override_env_var)
        else:
            found_program_name = name

        found_program_name = shutil.which(found_program_name) if found_program_name else ""

        if not found_program_name or not Path(found_program_name).is_file():
            found_program_name = ""

        _programs_path[name] = found_program_name
        _programs_searched[name] = True

    if not _programs_path[name] and required:
        raise FileNotFoundError(_not_found_error_message(name, override_env_var))

    return _programs_path[name]


def _not_found_error_message(name: str, override_env_var: str = "") -> str:
    return f"Program `{name}` not found in PATH. Supply one with `{override_env_var}` environment variable."


def get_gnu_assembler(required: bool = True) -> str:
    """
    Determine whether the gnu assembler is available on this system.
    """

    return _get_program("as", "AS", required)


def get_objdump(required: bool = True) -> str:
    """
    Determine whether binutils objdump is available on this system.
    """

    return _get_program("objdump", "OBJDUMP", required)


def get_objcopy(required: bool = True) -> str:
    """
    Determine whether binutils objcopy is available on this system.
    """

    return _get_program("objcopy", "OBJCOPY", required)


__all__ = [
    "get_gnu_assembler",
    "get_objdump",
    "get_objcopy",
]
