"""
Types used by in-debugger agent that requires gdb.
"""
from typing import Callable

import gdb


class AgentTestBreakpoint(gdb.Breakpoint):
    """
    Automatically perform the specified action when this breakpoint is hit.

    The action should normally be partially evaluated `agent_on_breakpoint`.
    """

    def __init__(self, spec, action: Callable[[gdb.BP_BREAKPOINT], None]):
        super().__init__(spec, gdb.BP_BREAKPOINT)
        self._action = action

    def stop(self):
        self._action(self)
        return False
