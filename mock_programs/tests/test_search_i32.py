#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# Basic test driver with the mock program looking for an i32.
# Source this script from gdb after the cheat gdb script has been loaded.

import logging
from pathlib import Path

from cheats_core import SearchSession, ValueType
from cheats_search import MemorySearchImpl
from testlib import stacktrace_on_error

_logger = logging.getLogger(Path(__file__).name)


@stacktrace_on_error
def test_i32_search_builtin():
    search_session = SearchSession(value_type=ValueType.I32)
    search_session.populate(65555, "gdb", MemorySearchImpl.address_filter_true)


@stacktrace_on_error
def test_i32_search_mp():
    search_session = SearchSession(value_type=ValueType.I32)
    search_session.populate(65555, "mp", MemorySearchImpl.address_filter_true)


if __name__ == "__main__":
    test_i32_search_builtin()
    test_i32_search_mp()
