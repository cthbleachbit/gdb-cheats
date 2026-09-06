#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# Basic test driver with the mock program looking for an i32.
# Source this script from gdb after the cheat gdb script has been loaded.

import logging
from pathlib import Path

from .testlib_fixtures import execute_in_gdb

_logger = logging.getLogger(Path(__file__).name)

INFERIOR = "bin_mock_program_debug"
INFERIOR_DIR = Path(__file__).parent / "mock_programs"


@execute_in_gdb(inferior=INFERIOR, inferior_path=INFERIOR_DIR,
                breakpoint_spec="mock_program.cpp:45")
def test_i32_search_builtin(gdb_cheats, gdb):
    search_session = gdb_cheats.core.SearchSession(value_type=gdb_cheats.core.ValueType.I32)
    search_session.populate(65555, "gdb", gdb_cheats.search.MemorySearchImpl.address_filter_true)

    # Make sure we find matches.
    matches = search_session.search_state()
    assert len(matches) > 100


@execute_in_gdb(inferior=INFERIOR, inferior_path=INFERIOR_DIR,
                breakpoint_spec="mock_program.cpp:45")
def test_i32_search_mp(gdb_cheats, gdb):
    search_session = gdb_cheats.core.SearchSession(value_type=gdb_cheats.core.ValueType.I32)
    search_session.populate(65555, "mp", gdb_cheats.search.MemorySearchImpl.address_filter_true)

    # Make sure we find matches.
    matches = search_session.search_state()
    assert len(matches) > 100
