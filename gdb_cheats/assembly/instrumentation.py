# SPDX-License-Identifier: GPL-3.0

"""
Looking for compiled blobs of assembly in GDB.
"""
import logging
from collections import defaultdict
from typing import Collection, Dict, Set, List, Any

import gdb

from .types import Snippet, InstrumentAction
from gdb_cheats.core import SearchSession, ValueType
from gdb_cheats.search import GdbBuiltInSearch
from gdb_cheats.utilities import Address

_logger = logging.getLogger(__name__)


class InstrumentationBreakpoint(gdb.Breakpoint):
    """
    A breakpoint that is used to instrument a snippet.
    """

    def __init__(self, snippet_name: str, address: Address, action: InstrumentAction,
                 search_variables: Dict[str, Any]) -> None:
        super().__init__(f"*{address}", gdb.BP_BREAKPOINT, internal=True)
        self.snippet_name = snippet_name
        self.address = address
        self.action = action
        self.search_variables = search_variables

    def stop(self) -> bool:
        self.action(gdb, self.search_variables)
        _logger.info(f"Instrumentation {self.action.as_label} fired at {self.address:016x}")
        return False


class CodeSearch:
    """
    Code search state.

    Maintains the state of code search, including snippet addresses and instrumentation breakpoints.
    """

    def __init__(self) -> None:
        # Where each snippet is found in memory
        self._snippet_addresses: Dict[str, Set[Address]] = defaultdict(set)
        self._snippet_breakpoints: Dict[str, List[gdb.Breakpoint]] = defaultdict(list)

        self._search_variables: Dict[str, Any] = {}

    def __del__(self) -> None:
        for breakpoints in self._snippet_breakpoints.values():
            for gdb_breakpoint in breakpoints:
                gdb_breakpoint.delete()

    def search_code(self, snippet: Snippet) -> Collection[Address]:
        """
        Look for the snippet and return the addresses where it was found.
        Only segments marked with executable permissions are searched.
        """
        raw_binary: bytes = snippet.assemble()

        search_session = SearchSession(ValueType.I8, None)
        search_engine = GdbBuiltInSearch(search_session.inferior)
        segments = search_session.discover_code_segments()
        search_areas = [(segment.start, segment.end) for segment in segments]

        matches = search_engine.exact(search_areas, raw_binary)
        if not matches:
            _logger.warning(f"Snippet {snippet.name} not found in memory.")
        else:
            _logger.info(f"Snippet {snippet.name} found at addresses: {matches}")

        self._snippet_addresses[snippet.name].update(matches)

        return self._snippet_addresses[snippet.name]

    def enable_instrumentation(self, snippet: Snippet) -> None:
        """
        Insert instrumentation for the snippet as breakpoints.
        """
        if snippet.name not in self._snippet_addresses.keys():
            raise ValueError(f"Snippet {snippet.name} has not been searched for.")

        if snippet.name in self._snippet_breakpoints.keys():
            _logger.info(f"Snippet {snippet.name} has active instrumentation breakpoints.")
            return

        if len(self._snippet_addresses[snippet.name]) == 0:
            _logger.warning(f"Snippet {snippet.name} has no addresses to instrument.")
            return

        # Look for instrumentation options in the snippet
        actions = snippet.instrumented_instructions

        for base_address in self._snippet_addresses[snippet.name]:

            for offset, action in actions.items():
                effective_address = base_address + offset

                _logger.info(f"Instrumenting {snippet.name}/{action.as_label} at {effective_address:016x}")
                action_breakpoint = InstrumentationBreakpoint(snippet.name,
                                                              effective_address,
                                                              action,
                                                              self._search_variables
                                                              )

                self._snippet_breakpoints[snippet.name].append(action_breakpoint)

    def disable_instrumentation(self, snippet: Snippet) -> None:
        """
        Remove instrumentation for the snippet.
        """
        if snippet.name not in self._snippet_breakpoints.keys() or not self._snippet_addresses[snippet.name]:
            _logger.warning(f"Snippet {snippet.name} has no active instrumentation breakpoints.")
            return

        current_breakpoints = self._snippet_breakpoints.pop(snippet.name)

        for gdb_breakpoint in current_breakpoints:
            gdb_breakpoint.delete()

        _logger.info(f"Removed instrumentation for {snippet.name}")

    def state(self) -> Dict[str, Any]:
        return self._search_variables


__all__ = ["CodeSearch"]
