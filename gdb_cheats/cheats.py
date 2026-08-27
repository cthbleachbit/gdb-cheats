#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# GDB cheats - Top Level Entry Point
# Source this script from gdb

import logging
import multiprocessing as mp
import shutil
import sys


def loader_entrypoint():
    """
    Entry point for the GDB cheats script.
    """
    try:
        import gdb
    except ImportError:
        logging.error("GDB API is not accessible. Is `cheats.py` sourced from gdb?")
        return

    # Load actual commands and start action
    from gdb_cheats.command import register_gdb_commands

    logging.basicConfig(level=logging.INFO)
    _logger = logging.getLogger("loader")

    try:
        # Workaround multiprocessing.spawn looking for /usr/bin/python (which is 2.7 on some systems)
        which_python = shutil.which(f"python{sys.version_info.major}.{sys.version_info.minor}")
        if not which_python:
            raise ValueError("Cannot determine python executable.")
        mp.set_executable(which_python)

        # Register commands and initialize session
        register_gdb_commands()
        gdb.execute("cheat session create")
    except Exception as e:
        logging.error("Cheat engine failed to initialize.", exc_info=e)


if __name__ == "__main__":
    loader_entrypoint()
