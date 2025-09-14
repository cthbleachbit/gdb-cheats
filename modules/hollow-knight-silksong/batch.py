#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

import functools
import logging
from typing import Dict, Tuple

from cheats_command import get_session
from cheats_core import SearchSession, ValueType, VariableDefinition
from cheats_search import MemorySearchImpl
from cheats_typing import Address, Offset

_logger = logging.getLogger("silksong")


def search_status_var(hp: int) -> None:
    """
    Populate search session to search for hp value.
    HP is always located at 4K page boundary + 0x21c.
    :param hp:   current hp value
    :return:
    """
    hp_alignment_filter = functools.partial(
        MemorySearchImpl.address_filter_alignment_offset,
        alignment=4096,
        offset=0x21c,
    )
    hp_value_filter = functools.partial(int.__le__, hp)
    search = get_session().current_search
    if search is None or len(search.search_state()) == 0:
        get_session().current_search = SearchSession(ValueType.U32)
        get_session().current_search.populate_filter(search_impl="mp", target_filter=hp_value_filter, address_filter=hp_alignment_filter)
    else:
        _logger.info(f"Search session already populated: {search.search_state()}")


def create_mappings(base: Address, mapping: Dict[str, Tuple[ValueType, Offset]]) -> None:
    for name, (value, offset) in mapping.items():
        get_session().variables.append(VariableDefinition(name, value, base + offset))


def define_status_vars(status_base: Address) -> None:
    mapping: Dict[str, Tuple[ValueType, Offset]] = {
        "hp": (ValueType.U32, 0x21c),
        "rosaries": (ValueType.U32, 0x23c),
        "silk": (ValueType.U32, 0x240),
        "bone_shards": (ValueType.U32, 0x908),
    }

    create_mappings(status_base, mapping)


def define_tool_vars(tool_base: Address) -> None:
    # FIXME: This seems to be in the order of discovery, not by internal IDs
    # There's probably a second look up table somewhere
    #
    # Note that all item entries seems to consists of 24bytes
    # bytes 0-7 = some weird pointer
    # bytes 8-12 = 0x10001
    # bytes 13-16 = item count
    #
    mapping: Dict[str, Tuple[ValueType, Offset]] = {
        "sting_shard": (ValueType.U32, 0x0ac),
        "longpin": (ValueType.U32, 0x10c),
        "flintslate": (ValueType.U32, 0x124),
        "curveclaw": (ValueType.U32, 0x13c),
        "straight_pin": (ValueType.U32, 0x19c),
        "flea_brew": (ValueType.U32, 0x1b4),
        "cogwork_wheel": (ValueType.U32, 0x2a4),
        "plasmium_phial": (ValueType.U32, 0x304),
        "delvers_drill": (ValueType.U32, 0x37c),
        "cogfly": (ValueType.U32, 0x3c4),
        "silkshot": (ValueType.U32, 0x424),
        "tacks": (ValueType.U32, 0x454),
        "conchcutter": (ValueType.U32, 0x46c),
        "throwing_ring": (ValueType.U32, 0x484),
        "rosary_cannon": (ValueType.U32, 0x4cc),
        "threefold_pin": (ValueType.U32, 0x55c),
        "pimpillo": (ValueType.U32, 0x574),
        "curvesickle": (ValueType.U32, 0x58c),
    }

    create_mappings(tool_base, mapping)
