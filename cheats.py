#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# GDB cheats - Top Level Entry Point
# Source this script from gdb

import logging
import sys
from pathlib import Path

import gdb

# Append script directory
if str(Path(__file__).parent) not in sys.path:
    sys.path.append(str(Path(__file__).parent))

# Load actual commands and start action
from cheats_command import register_gdb_commands

logging.basicConfig(level=logging.INFO)
try:
    register_gdb_commands()
    gdb.execute("cheat session create")
except Exception as e:
    logging.error("Failed to register gdb commands", exc_info=e)
