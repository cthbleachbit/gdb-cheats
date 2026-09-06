# SPDX-License-Identifier: GPL-3.0

"""
Manages session separation.

The command line user has the default session but can switch to a different session.
Each session has its own separate variable search history, variable definitions, and lock watchpoints.

"""
import logging
from collections import defaultdict
from typing import Optional, Dict

from gdb_cheats.core import CheatSession

# Stores active sessions.
# A `None` key is reserved for the command line session.
# Contrib scripts should create their own sessions.
_sessions: Dict[Optional[str], CheatSession] = defaultdict(CheatSession)

_logger = logging.getLogger(__name__)


def get_or_create_session(session_key: Optional[str] = None) -> CheatSession:
    """
    Returns the selected session.
    """
    try:
        return _sessions[session_key]
    except KeyError:
        _logger.info("Creating new session `%s`.", session_key)
        _sessions[session_key] = CheatSession()
        return _sessions[session_key]


def destroy_session(session_key: Optional[str]):
    """
    Destroys the selected session.
    """
    try:
        session = _sessions.pop(session_key)
        if session is not None:
            _logger.info("Destroying session `%s`", session_key)
            session.cleanup()
    except KeyError:
        _logger.warning("Session to destroy `%s` does not exist.", session_key)


def summarize_all_session():
    global _sessions

    for name, session in _sessions.items():
        print("##### Session: ", name or "(gdb command line)")
        session.summarize()
        if session.current_search is not None:
            session.current_search.summarize(True)
