#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# Test scaffolding - sets up search and include paths.
# Source this before any other tests.


import sys
from pathlib import Path

import gdb

if __name__ == "__main__":
    # Append script directory
    test_base_dir = Path(__file__).parent
    if str(test_base_dir) not in sys.path:
        sys.path.append(str(test_base_dir))
        gdb.execute(" ".join(["directory", str(test_base_dir), ]))
