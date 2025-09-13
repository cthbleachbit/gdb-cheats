#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# GDB Cheats - GDB Command Frontend

import argparse
import functools
import logging
import sys
from time import sleep
from typing import Optional

import gdb
import tqdm

from cheats_core import ValueType, CheatSession, SearchSession, InferiorState, VariableDefinition
from cheats_search import MemorySearchImpl

_logger = logging.getLogger("command")


class SoftErrorArgumentParser(argparse.ArgumentParser):
    """
    Modified argument parser that raises exceptions instead of exiting
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise ValueError(message)

    def exit(self, status=0, message=None):
        raise StopIteration(message)


# Global State ================================================================

_session: Optional[CheatSession] = None


def get_session() -> Optional[CheatSession]:
    """
    Returns the current session for automation modules
    :return: current session
    """
    return _session


# GDB Prefix Commands =========================================================

class PrefixCheat(gdb.Command):
    """
    Cheat engine top level prefix

    Usage: cheat <subcommand>
    """

    def __init__(self):
        super(PrefixCheat, self).__init__(
            "cheat", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatSession(gdb.Command):
    """
    Manage session wide settings

    Usage: cheat session <subcommand>
    """

    def __init__(self):
        super(PrefixCheatSession, self).__init__(
            "cheat session", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatSearch(gdb.Command):
    """
    Control memory search

    Usage: cheat search <subcommand>
    """

    def __init__(self):
        super(PrefixCheatSearch, self).__init__("cheat search",
                                                gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatLock(gdb.Command):
    """
    Control memory content locking at specific addresses

    Usage: cheat session <subcommand>
    """

    def __init__(self):
        super(PrefixCheatLock, self).__init__("cheat lock",
                                              gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatVariable(gdb.Command):
    """
    Manage variable definitions

    Usage: cheat variable <subcommand>
    """

    def __init__(self):
        super(PrefixCheatVariable, self).__init__(
            "cheat variable", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


# GDB Commands ================================================================


class CommandCheatSessionCreate(gdb.Command):
    """
    Create a new cheat session.

    Usage: cheat session create
    """

    def __init__(self):
        super(CommandCheatSessionCreate, self).__init__(
            "cheat session create",
            gdb.COMMAND_USER,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()

        if _session is not None:
            _session.cleanup()

        _session = CheatSession()

        # Also do environmental setup
        # Unity games use SIGPWR, SIGXCPU, SIGUSR1, SIGUSR2 for some reason.
        # Make sure GDB don't stop on these signals and pass them to programs unchanged instead.
        _logger.info(f"Setting signal handling behavior for certain games...")
        for signal in ["SIGPWR", "SIGXCPU", "SIGUSR1", "SIGUSR2"]:
            gdb.execute(
                f"handle {signal} nostop noprint noignore", from_tty=from_tty)


class CommandCheatSessionSummary(gdb.Command):
    """
    Print a summary of the current cheat session.
    This includes all variables and watchpoints defined in this cheat session and current search (if one is in progress).

    Usage: cheat session summary
    """

    def __init__(self):
        super(CommandCheatSessionSummary, self).__init__(
            "cheat session summary",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session

        if _session is None:
            _logger.error("No cheat session found.")
            return

        _session.summarize_variables()
        _session.summarize_watchpoints()

        # Active search
        CommandCheatSearchSummary.summarize(from_tty)


class CommandCheatSessionDelete(gdb.Command):
    """
    Clean up current cheat session. Remove all variables and watchpoints.
    Usage: cheat session delete
    """

    def __init__(self):
        super(CommandCheatSessionDelete, self).__init__(
            "cheat session delete",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")

        _session.cleanup()
        _session = None


class CommandCheatSearchCreate(gdb.Command):
    """
    Start a new cheat search session.
    Usage: cheat search create <target variable type>
    """

    def __init__(self):
        super(CommandCheatSearchCreate, self).__init__(
            "cheat search create",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()

        if _session is None:
            _logger.error("No cheat session found.")
            return

        argv = gdb.string_to_argv(argument)
        if len(argv) != 1:
            _logger.error(
                "Invalid number of arguments. Pass exactly 1 argument indicating variable type: uint8_t, i16 etc.")
            return

        value_type = ValueType.from_short_hand(argv[0])
        if value_type is None:
            _logger.error(f"Unknown value type: {argv[0]}")
            return

        _session.current_search = SearchSession(value_type)
        _session.current_search.max_print_limit = 100


class CommandCheatSearchPopulate(gdb.Command):
    """
    Populate a cheat search session.
    Usage: cheat search populate <initial value to search>
    """

    def __init__(self):
        super(CommandCheatSearchPopulate, self).__init__(
            "cheat search populate",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )
        self.argument_parser = SoftErrorArgumentParser(
            description="Populate initial candidate pointers.",
            exit_on_error=False,
        )
        self.argument_parser.add_argument(
            "--search-impl", "-s",
            type=str,
            help="Search implementation type. 'gdb' or 'mp'",
            default="gdb",
            dest="search_impl",
        )
        self.argument_parser.add_argument(
            "--alignment", "-a",
            type=int,
            help="Variable alignment",
            default=1,
        )
        self.argument_parser.add_argument(
            "--offset", "-o",
            type=functools.partial(int, base=0),
            help="Variable offset from alignment",
            default=0,
        )
        self.argument_parser.add_argument(
            "search_value",
            type=str,
            help="Value to search for.",
            nargs='?',
            default=None,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()

        if _session is None:
            _logger.error("No cheat session found.")
            return
        if _session.current_search is None:
            _logger.error("No variable search in progress.")
            return

        argv = gdb.string_to_argv(argument)
        try:
            parsed_args = self.argument_parser.parse_args(argv)
        except StopIteration:
            return
        except Exception as e:
            _logger.error(f"Argument parsing failed: {e}", exc_info=None)
            return

        if parsed_args.alignment < 1:
            address_filter = MemorySearchImpl.address_filter_true
        else:
            address_filter = functools.partial(
                MemorySearchImpl.address_filter_alignment_offset,
                alignment=parsed_args.alignment,
                offset=parsed_args.offset
            )

        try:
            if _session.current_search.value_type.is_integral:
                target_value = int(parsed_args.search_value, 0)
            else:
                target_value = float(parsed_args.search_value)

            _session.current_search.populate(target_value, parsed_args.search_impl, address_filter)
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatSearchNarrow(gdb.Command):
    """
    Narrow down a cheat search session.
    Usage: cheat search narrow [--poll N] [--interval SECONDS] <value to search>
    """

    def __init__(self):
        super(CommandCheatSearchNarrow, self).__init__(
            "cheat search narrow",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )
        self.argument_parser = SoftErrorArgumentParser(
            description="Narrow down area of memory value search.",
            exit_on_error=False,
        )
        self.argument_parser.add_argument(
            "--poll", "-p",
            type=int,
            default=0,
            help="Poll this many times periodically while running",
            dest="poll",
        )
        self.argument_parser.add_argument(
            "--interval", "-i",
            type=int,
            default=5,
            help="Polling interval in seconds. Defaults to 5.",
            dest="interval",
        )
        self.argument_parser.add_argument(
            "--search-impl", "-s",
            type=str,
            help="Search implementation type. 'gdb' or 'mp'",
            default="gdb",
            dest="search_impl",
        )
        self.argument_parser.add_argument(
            "search_value", type=str, help="Value to search for", nargs='?', default=None
        )

    @staticmethod
    def arg_parse_error(message: str) -> None:
        _logger.error(message)

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()

        if _session is None:
            _logger.error("No cheat session found.")
            return
        if _session.current_search is None:
            _logger.error("No variable search in progress.")
            return

        argv = gdb.string_to_argv(argument)
        try:
            parsed_args = self.argument_parser.parse_args(argv)
        except StopIteration:
            return
        except Exception as e:
            _logger.error(f"Argument parsing failed: {e}", exc_info=None)
            return

        if parsed_args.poll < 0:
            _logger.error(
                f"Polling counts must be positive: {parsed_args.poll}")
            return

        if parsed_args.interval < 1:
            _logger.error(f"Interval must be positive: {parsed_args.interval}")

        try:
            if _session.current_search.value_type.is_integral:
                search_value = int(parsed_args.search_value, 0)
            else:
                search_value = float(parsed_args.search_value)

            if parsed_args.poll == 0:
                # One-shot narrow
                with InferiorState(gdb.selected_inferior(), "pause"):
                    _session.current_search.narrow(search_value, parsed_args.search_impl)
                return

            # Polling mode
            with InferiorState(gdb.selected_inferior(), "run"):
                for polled in tqdm.tqdm(range(parsed_args.poll), desc="Polling...", unit="attempt"):
                    with InferiorState(gdb.selected_inferior(), "pause"):
                        _session.current_search.narrow(search_value, parsed_args.search_impl)

                    if polled == parsed_args.poll - 1:
                        break
                    else:
                        _logger.info("Waiting between searches...")
                        sleep(parsed_args.interval)
        except KeyboardInterrupt:
            _logger.error("User interrupted.")
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatSearchSummary(gdb.Command):
    """
    Print a summary of the current cheat session.
    Usage: cheat search summary
    """

    def __init__(self):
        super(CommandCheatSearchSummary, self).__init__(
            "cheat search summary",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )
        self.argument_parser = SoftErrorArgumentParser(
            description="Print a summary of the current candidate pointers.",
            exit_on_error=False,
        )
        self.argument_parser.add_argument(
            "--limit", "-l",
            type=int,
            default=100,
            help="Limit the number of candidates to print.",
        )

    @staticmethod
    def summarize(from_tty: bool, print_limit: int = 100) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        if _session.current_search is None:
            print("=== No variable search in progress ===")
            return

        _session.current_search.summarize(from_tty, print_limit)

    def invoke(self, argument: str, from_tty: bool) -> None:
        argv = gdb.string_to_argv(argument)
        try:
            parsed_args = self.argument_parser.parse_args(argv)
        except StopIteration:
            return
        except Exception as e:
            _logger.error(f"Argument parsing failed: {e}", exc_info=None)
            return

        CommandCheatSearchSummary.summarize(from_tty, parsed_args.limit)
        return


class CommandCheatSearchDefineVariable(gdb.Command):
    """
    Define a cheat variable and add it to the global session state.
    Usage: cheat search define_variable <variable name> [search result index, default 0]
    """

    def __init__(self):
        super(CommandCheatSearchDefineVariable, self).__init__(
            "cheat search define_variable",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return
        if _session.current_search is None:
            print("No variable search in progress.")
            return

        # Parse and validate arguments
        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error(
                "Usage: cheat_search_variable <variable name> [search result index, default 0]")
            return

        index = int(argv[1]) if len(argv) > 1 else 0

        # Actual work
        try:
            candidates = _session.current_search.search_state()
            if index >= len(candidates):
                _logger.error("Invalid search result index.")
                return

            address = candidates[index][0]
            variable = _session.current_search.define_variable(
                argv[0], address)

            if variable is not None:
                _session.variables.append(variable)
                _logger.info(f"New variable {variable.name} defined.")
                _session.summarize_variables()
        except gdb.error as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatSearchReset(gdb.Command):
    """
    Define a cheat variable and add it to the global session state.
    Usage: cheat search reset <variable name>
    """

    def __init__(self):
        super(CommandCheatSearchReset, self).__init__(
            "cheat search reset",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return
        if _session.current_search is None:
            print("No variable search in progress.")
            return

        _session.current_search.reset()


class CommandCheatLockCreate(gdb.Command):
    """
    Create a new lock that locks a defined variable to a defined value.
    Usage: cheat lock create <variable index> <locked value>
    """

    def __init__(self):
        super(CommandCheatLockCreate, self).__init__(
            "cheat lock create",
            gdb.COMMAND_TRACEPOINTS,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Parse and validate argument
        argv = gdb.string_to_argv(argument)
        if len(argv) != 2:
            _logger.error(
                "Invalid number of arguments. Pass exactly 2 argument for variable def index and lock-in value.")
            return

        variable_index = int(argv[0], 0)
        locked_value_str = argv[1]

        # Actual work
        try:
            if variable_index > len(_session.variables):
                _logger.error("Invalid variable index.")
                return
            variable = _session.variables[variable_index]

            if not variable.valid:
                _logger.error("Invalid variable.")

            if variable.value_type.is_integral:
                locked_value = int(locked_value_str, 0)
            else:
                locked_value = float(locked_value_str)

            _session.variable_lock_create(variable, locked_value)
            _session.summarize_watchpoints()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatLockEnable(gdb.Command):
    """
    Enable a created lock on a defined variable.
    Usage: cheat lock enable <variable index>
    """

    def __init__(self):
        super(CommandCheatLockEnable, self).__init__(
            "cheat lock enable",
            gdb.COMMAND_TRACEPOINTS,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Parse and validate arguments
        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error(
                "Invalid number of arguments. Pass exactly 1 argument for variable def index.")
            return

        variable_index = int(argv[0], 0)

        # Actual work
        try:
            if variable_index > len(_session.variables):
                _logger.error("Invalid variable index.")
                return
            variable = _session.variables[variable_index]

            if not variable.valid:
                _logger.error("Invalid variable.")

            _session.variable_lock_enable(variable)
            _session.summarize_watchpoints()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatLockDisable(gdb.Command):
    """
    Enable a created lock on a defined variable.
    Usage: cheat lock enable <variable index>
    """

    def __init__(self):
        super(CommandCheatLockDisable, self).__init__(
            "cheat lock disable",
            gdb.COMMAND_TRACEPOINTS,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Parse and validate arguments
        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error(
                "Invalid number of arguments. Pass exactly 1 argument for variable def index.")
            return

        variable_index = int(argv[0], 0)

        # Actual work:
        try:
            if variable_index > len(_session.variables):
                _logger.error("Invalid variable index.")
                return
            variable = _session.variables[variable_index]

            if not variable.valid:
                _logger.error("Invalid variable.")

            _session.variable_lock_disable(variable)
            _session.summarize_watchpoints()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatLockDelete(gdb.Command):
    """
    Delete a created lock on a defined variable.
    Usage: cheat lock delete <variable index>
    """

    def __init__(self):
        super(CommandCheatLockDelete, self).__init__(
            "cheat lock delete",
            gdb.COMMAND_TRACEPOINTS,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Parse and validate arguments
        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error(
                "Invalid number of arguments. Pass exactly 1 argument for variable def index."
            )
            return

        variable_index = int(argv[0], 0)

        # Actual work
        try:
            if variable_index > len(_session.variables):
                _logger.error("Invalid variable index.")
                return
            variable = _session.variables[variable_index]

            if not variable.valid:
                _logger.error("Invalid variable.")

            _session.variable_lock_delete(variable)
            _session.summarize_watchpoints()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatVariableCreate(gdb.Command):
    """
    Manually define a new variable.
    Usage: cheat variable create <name> <type> <address>
    """

    def __init__(self):
        super(CommandCheatVariableCreate, self).__init__(
            "cheat variable create",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Parse and validate arguments
        argv = gdb.string_to_argv(argument)
        if len(argv) != 3:
            _logger.error(
                "Usage: cheat_variable_create <name> <type> <address>")
            return
        name = argv[0]
        value_type = ValueType.from_short_hand(argv[1])
        if value_type is None:
            _logger.error(f"Unable to parse data type {argv[1]}")
            return
        address = int(argv[2], 0)

        # Actual work
        try:
            if address in [v.address for v in _session.variables if v.valid]:
                _logger.error(f"Address {address} already exists.")
            else:
                _session.variables.append(
                    VariableDefinition(name, value_type, address))

            _session.summarize_variables()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatVariableSet(gdb.Command):
    """
    Set value for variable.
    Usage: cheat variable set <index> <value>
    """

    def __init__(self):
        super(CommandCheatVariableSet, self).__init__(
            "cheat variable set",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Parse and validate arguments
        argv = gdb.string_to_argv(argument)
        if len(argv) != 2:
            _logger.error("Usage: cheat_variable_set <index> <value>")
            return
        index = int(argv[0], 0)
        value_str = argv[1]

        # Actual work
        try:
            if index > len(_session.variables):
                _logger.error("Invalid variable index.")
                return

            variable = _session.variables[index]
            if not variable.valid:
                _logger.error("Invalid variable.")
                _session.summarize_variables()
                return
            if variable in _session.watchpoints.keys():
                _logger.error(
                    f"Variable {variable} is in-use by one of the watchpoints. Update the watchpoint instead.")
                _session.summarize_watchpoints()
                return

            if variable.value_type.is_integral:
                value = int(value_str, 0)
            else:
                value = float(value_str)

            variable.set(value)
            _session.summarize_variables()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatVariableDelete(gdb.Command):
    """
    Delete variable.
    Usage: cheat variable delete <index>
    """

    def __init__(self):
        super(CommandCheatVariableDelete, self).__init__(
            "cheat variable delete",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()
        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Parse and validate arguments
        argv = gdb.string_to_argv(argument)
        if len(argv) != 1:
            _logger.error("Usage: cheat_variable_delete <index>")
            return
        index = int(argv[0], 0)

        # Actual work
        try:
            if index > len(_session.variables):
                _logger.error("Invalid variable index.")
                return

            variable = _session.variables[index]
            if not variable.valid:
                _logger.error("Invalid variable.")
                _session.summarize_variables()
                return
            if variable in _session.watchpoints.keys():
                _logger.error(
                    f"Variable {variable} is in-use by one of the watchpoints and cannot be deleted.")
                _session.summarize_watchpoints()
                return

            _session.variables[index].valid = False
            _session.summarize_variables()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


class CommandCheatVariableSummary(gdb.Command):
    """
    Print a list of variable and their current in-memory values.

    Usage: cheat_variable_summary
    """

    def __init__(self):
        super(CommandCheatVariableSummary, self).__init__(
            "cheat variable summary",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session

        if _session is None:
            _logger.error("No cheat session found.")
            return

        # Actual work
        try:
            _session.summarize_variables()
        except Exception as e:
            _logger.error(f"Error occurred during operation", exc_info=e)
            return


# GDB Command registration ====================================================

def register_gdb_commands():
    PrefixCheat()
    PrefixCheatSession()
    PrefixCheatSearch()
    PrefixCheatLock()
    PrefixCheatVariable()

    CommandCheatSessionCreate()
    CommandCheatSessionSummary()
    CommandCheatSessionDelete()
    CommandCheatSearchCreate()
    CommandCheatSearchPopulate()
    CommandCheatSearchNarrow()
    CommandCheatSearchSummary()
    CommandCheatSearchDefineVariable()
    CommandCheatSearchReset()
    CommandCheatLockCreate()
    CommandCheatLockEnable()
    CommandCheatLockDisable()
    CommandCheatLockDelete()
    CommandCheatVariableCreate()
    CommandCheatVariableSet()
    CommandCheatVariableDelete()
    CommandCheatVariableSummary()


# Prevent direct usage
if __name__ == "__main__":
    print("You should not source this file directly. Use top level cheats.py instead.", file=sys.stderr)
