#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

import functools
import logging

from cheats_command import get_session
from cheats_core import SearchSession, ValueType
from cheats_search import MemorySearchImpl

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
