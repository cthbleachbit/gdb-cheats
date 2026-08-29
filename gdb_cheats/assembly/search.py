"""
Looking for assembly instructions in GDB.
"""
from typing import Collection

from .types import Snippet
from ..core import SearchSession, ValueType, CheatSession
from ..search import GdbBuiltInSearch
from ..utilities import Address


def apply_snippet_search(session: CheatSession, snippet: Snippet) -> Collection[Address]:
    """
    Apply the snippet to memory and return the addresses where it was found.
    """
    raw_binary: bytes = snippet.assemble()

    search_session = SearchSession(ValueType.I8, session.libc_constants)
    search_engine = GdbBuiltInSearch(search_session.inferior)
    segments = search_session.discover_segments()
    search_areas = [(segment.start, segment.end) for segment in segments]

    return search_engine.exact(search_areas, raw_binary)
