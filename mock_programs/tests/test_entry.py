#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# Test scaffolding - Sets up initial breakpoints.
# Source this before any test cases.


import gdb

from cheats_command import set_verbose_logging

if __name__ == "__main__":
    set_verbose_logging(True)
    # Setup breakpoints\
    gdb.execute("break mock_program.cpp:45")
    gdb.execute("run")
