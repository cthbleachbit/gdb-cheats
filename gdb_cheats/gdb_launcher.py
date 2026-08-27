# SPDX-License-Identifier: GPL-3.0

"""
Launches GDB with cheats loaded.
"""
import importlib
import logging
import os
import shlex
import shutil
import sys
from pathlib import Path

_logger = logging.getLogger(__name__)


def launch_gdb():
    """
    Start GDB with cheats loaded via `-iex`

    Pass all other arguments to GDB.
    """

    logging.basicConfig(level=logging.INFO)

    try:
        cheats_module = importlib.import_module("gdb_cheats")
        cheats_entrypoint = importlib.import_module("gdb_cheats.cheats")
    except ImportError:
        _logger.critical("Unable to import `gdb_cheats.cheats` module.")
        return 1

    if cheats_entrypoint.__file__ is None or cheats_module.__path__ is None:
        _logger.critical("Unable to determine source file for `gdb_cheats.cheats` module.")
        return 2

    source_file = str(Path(cheats_entrypoint.__file__).resolve())
    search_path = Path(cheats_module.__path__[0]).resolve().parent

    _logger.info(f"Cheats module at {search_path}")
    commands = [
        "gdb",
        "-iex",
        f"python import sys; sys.path.append(\"{str(search_path)}\")",
        "-iex",
        f"source {shlex.quote(source_file)}",
        *sys.argv[1:]]

    gdb_program = shutil.which("gdb")
    if gdb_program is None:
        print("Unable to find `gdb`.", file=sys.stderr)
        return 3

    os.execve(gdb_program, argv=commands, env=os.environ)
