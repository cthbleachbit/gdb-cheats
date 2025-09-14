#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# GDB Cheats - Type annotations

from typing import TypeAlias, Union, Callable

Address: TypeAlias = int
Offset: TypeAlias = int
Numeric: TypeAlias = Union[int, float]
Buffer: TypeAlias = Union[bytes, memoryview]

ValuePredicate: TypeAlias = Callable[[Buffer], bool]
AddressPredicate: TypeAlias = Callable[[Address], bool]
