#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# Basic test driver with the mock program looking for an i32.
# Source this script from gdb after the cheat gdb script has been loaded.

import logging
from pathlib import Path

from cheats_command import get_or_create_session
from cheats_core import CheatSession, SearchSession, ValueType
from cheats_search import MemorySearchImpl

_logger = logging.getLogger(Path(__file__).name)


def test_i32_search():
    session: CheatSession = get_or_create_session()

    search_session = SearchSession(value_type=ValueType.I32)
    search_session.populate(65555, "gdb", MemorySearchImpl.address_filter_true)


if __name__ == "__main__":
    test_i32_search()
