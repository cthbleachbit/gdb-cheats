#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0
import argparse
import logging
import struct
from time import sleep

_logger = logging.getLogger("cheats")
logging.basicConfig(level=logging.INFO)

import gdb
import tqdm
from contextlib import AbstractContextManager
from typing import Optional, List, Dict, Tuple, Literal, Union
from enum import Enum


class InferiorState(AbstractContextManager):
    """
    Force inferior to enter a specified running state and restore upon exit
    """

    def __init__(self, inferior: gdb.Inferior, state: Literal["run", "pause"]):
        self.inferior = inferior
        self.should_run = state == "run"

    @staticmethod
    def _run():
        _logger.info("Continuing inferior execution")
        gdb.execute("continue &")

    @staticmethod
    def _stop():
        _logger.info("Pausing inferior execution")
        gdb.execute("interrupt -a")

    def __enter__(self) -> None:
        if self.inferior.pid == 0:
            raise ValueError("Inferior is not running.")

        self.was_running = any(t.is_running() for t in self.inferior.threads() if t.is_valid())
        if self.was_running == self.should_run:
            # Do nothing
            return

        if self.should_run:
            # Run the process in background execution mode
            InferiorState._run()
        else:
            # Stop all the threads
            InferiorState._stop()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.was_running == self.should_run:
            # Do nothing
            return

        if self.was_running:
            # Restore running state into background execution mode
            InferiorState._run()
        else:
            InferiorState._stop()


class SoftErrorArgumentParser(argparse.ArgumentParser):
    """
    Modified argument parser that raises exceptions instead of exiting
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise ValueError(message)

    def exit(self, status=0, message=None):
        pass



class ValueType(str, Enum):
    I8 = "char",
    I16 = "short",
    I32 = "int",
    I64 = "long",
    U8 = "unsigned char",
    U16 = "unsigned short",
    U32 = "unsigned int",
    U64 = "unsigned long",
    F32 = "float",
    F64 = "double",

    def format_spec(self, address: int) -> str:
        """ Format to gdb acceptable spec """
        return f"*({self}*)0x{address:016x}"

    @property
    def length_bytes(self) -> int:
        """ Return the length of the value in number of bytes."""
        if self == ValueType.I8 or self == ValueType.U8:
            return 1
        elif self == ValueType.I16 or self == ValueType.U16:
            return 2
        elif self == ValueType.I32 or self == ValueType.U32 or self == ValueType.F32:
            return 4
        elif self == ValueType.I64 or self == ValueType.U64 or self == ValueType.F64:
            return 8

    @property
    def signed(self) -> bool:
        """ Return True if the value is signed. """
        lookup_table = {
            ValueType.I8: True,
            ValueType.U8: False,
            ValueType.I16: True,
            ValueType.U16: False,
            ValueType.I32: True,
            ValueType.U32: False,
            ValueType.I64: True,
            ValueType.U64: False,
            ValueType.F32: True,
            ValueType.F64: True,
        }

        return lookup_table[self]

    @property
    def is_integral(self) -> bool:
        """ Return True if the value is integer. """
        return self and self != ValueType.F32 and self != ValueType.F64

    @property
    def is_floating_point(self) -> bool:
        """ Return True if the value is floating point. """
        return self and self == ValueType.F32 and self == ValueType.F64

    @staticmethod
    def from_short_hand(notation: str) -> Optional["ValueType"]:
        """
        Parse a user specified type string to enum value.
        :param notation: user input
        :return:     Value type enum if parsed successfully. otherwise None
        """
        lookup_table = {
            "u8": ValueType.U8,
            "u16": ValueType.U16,
            "u32": ValueType.U32,
            "u64": ValueType.U64,
            "i8": ValueType.I8,
            "i16": ValueType.I16,
            "i32": ValueType.I32,
            "i64": ValueType.I64,
            "f32": ValueType.F32,
            "f64": ValueType.F64,
        }

        notation_normalized = notation.lower()
        try:
            return ValueType(notation_normalized)
        except ValueError:
            pass

        return lookup_table.get(notation_normalized, None)

    @property
    def short_hand(self) -> str:
        """ Return a short notation of the value type: i8, u8, etc."""
        lookup_table = {
            ValueType.I8: "i8",
            ValueType.I16: "i16",
            ValueType.I32: "i32",
            ValueType.I64: "i64",
            ValueType.U8: "u8",
            ValueType.U16: "u16",
            ValueType.U32: "u32",
            ValueType.U64: "u64",
            ValueType.F32: "f32",
            ValueType.F64: "f64",
        }

        return lookup_table[self]

    def from_buffer(self, buffer: bytes) -> Union[int, float]:
        """
        Create a value from a byte buffer. The buffer must be large enough to fit the data type.

        If the buffer is not large enough to fit the data type, an exception will be raised.

        :param buffer:  buffer to decode
        :return: decoded integer or float
        """
        if not self:
            raise ValueError(f"Invalid value type {self}")

        if len(buffer) < self.length_bytes:
            raise ValueError(f"Buffer too small! Need {self.length_bytes} bytes to encode {self}, only have {len(buffer)} bytes.")

        if self.is_integral:
            return int.from_bytes(buffer[0:self.length_bytes], "little")
        elif self == ValueType.F32:
            return struct.unpack('f', buffer[0:self.length_bytes])[0]
        elif self == ValueType.F64:
            return struct.unpack('d', buffer[0:self.length_bytes])[0]
        else:
            raise ValueError(f"Invalid value type {self}")

    def to_buffer(self, value: Union[int, float]) -> bytes:
        """
        Encode an integer or float to a byte buffer.
        :param value:  value to encode
        :return:       encoded buffer
        """
        if not self:
            raise ValueError(f"Invalid value type {self}")

        if self.is_integral:
            return int(value).to_bytes(self.length_bytes, "little")
        elif self == ValueType.F32:
            return struct.pack('f', value)
        elif self == ValueType.F64:
            return struct.pack('d', value)
        else:
            raise ValueError(f"Invalid value type {self}")

    def to_readable(self, value_or_buffer: Union[int, float, bytes]) -> str:
        """
        Format a value or buffer into a readable hexdump-like string.
        :param value_or_buffer:  value or buffer to format
        :return: formatted hexdump-like string
        """
        if isinstance(value_or_buffer, int) or isinstance(value_or_buffer, float):
            buffer = self.to_buffer(value_or_buffer)
        else:
            buffer = value_or_buffer

        return " ".join([f"{b:02x}" for b in buffer])


class VariableDefinition:
    def __init__(self, name: str, value_type: ValueType, address: int):
        self.name = name
        self.value_type = value_type
        self.address = address
        self.valid = True

    def format_spec(self) -> str:
        """ Format to gdb acceptable spec """
        return self.value_type.format_spec(self.address)

    def set(self, value: Union[int, float]) -> None:
        """ Set value to buffer """
        process = gdb.selected_inferior()
        buffer = self.value_type.to_buffer(value)
        process.write_memory(self.address, buffer, self.value_type.length_bytes)

    def get(self) -> Optional[Tuple[Union[int, float], str]]:
        """ Get value from buffer """
        process = gdb.selected_inferior()
        try:
            buffer = bytes(process.read_memory(self.address, self.value_type.length_bytes))
        except gdb.MemoryError:
            _logger.error(f"Failed to get value from variable {self.name} at 0x{self.address:016x}")
            return None

        value = self.value_type.from_buffer(buffer)
        buffer_string = self.value_type.to_readable(value)
        return value, buffer_string

    def __eq__(self, other) -> bool:
        if not isinstance(other, VariableDefinition):
            return False
        return self.name == other.name and self.value_type == other.value_type and self.address == other.address and self.valid == other.valid

    def __repr__(self) -> str:
        return f"VariableDefinition({self.name}, {self.value_type}, 0x{self.address:016x}, {self.valid})"

    def __hash__(self) -> int:
        return hash((self.name, self.value_type, self.address, self.valid))


class LockedValueWatchpoint(gdb.Breakpoint):
    def __init__(self, variable: VariableDefinition, value: Union[int, float]):
        super().__init__(variable.format_spec(), gdb.BP_WATCHPOINT, gdb.WP_WRITE, True)
        self.variable = variable
        self.value = value

    def stop(self):
        """Upon trigger force value overwrite"""
        self.variable.set(self.value)
        _logger.info(f"Watchpoint {self.variable.name}={self.value} fired.")

    def get_variable(self) -> VariableDefinition:
        return self.variable


class MemorySegmentPermission:
    def __init__(self, r: bool, w: bool, x: bool, p: bool):
        self.r = r
        self.w = w
        self.x = x
        self.p = p

    def __str__(self):
        r = "r" if self.r else "-"
        w = "w" if self.w else "-"
        x = "x" if self.x else "-"
        p = "p" if self.p else "-"
        return f"{r}{w}{x}{p}"

    def __repr__(self):
        return f"MemorySegmentPermission({str(self)})"

    @staticmethod
    def from_string(literal: str) -> "MemorySegmentPermission":
        r = literal[0] == "r"
        w = literal[1] == "w"
        x = literal[2] == "x"
        p = literal[3] == "p"
        return MemorySegmentPermission(r, w, x, p)


class MemorySegment:
    def __init__(self, start: int, end: int, permissions: MemorySegmentPermission, offset: int, device: str, inode: int,
                 pathname: str):
        self.start = start
        self.end = end
        self.permissions = permissions
        self.offset = offset
        self.device = device
        self.inode = inode
        self.pathname = pathname

    @staticmethod
    def from_proc_pid_map(line: str) -> Optional["MemorySegment"]:
        tokens = [t.strip() for t in line.strip().split()]
        if len(tokens) < 5:
            raise ValueError(f"Invalid /proc/pid/maps line: {line}")

        start_end = tokens[0]
        start, end = start_end.split("-")
        permissions = MemorySegmentPermission.from_string(tokens[1])
        offset = tokens[2]
        device = tokens[3]
        inode = tokens[4]
        if len(tokens) > 5:
            path = tokens[5]
        else:
            path = ""

        return MemorySegment(int(start, 16), int(end, 16), permissions, int(offset, 16), device, int(inode), path)

    @property
    def file_backed(self) -> bool:
        return self.pathname.startswith("/") and self.offset > 0

    @property
    def writable(self) -> bool:
        return self.permissions.w

    @property
    def readable(self) -> bool:
        return self.permissions.r

    def __len__(self) -> int:
        return self.end - self.start

    def __str__(self):
        return f"{self.start:016x}-{self.end:016x} {self.permissions} {self.offset:016x} {self.pathname}"

    def __repr__(self):
        return f"MemorySegment({str(self)})"

    def __hash__(self):
        return hash((self.start, self.end))


class SearchSession:
    """ Records search progress for a particular variable """

    def __init__(self, value_type: ValueType):
        """
        Create a new search session which records search progress for a particular variable.
        :param value_type: Type for this variable
        """
        self.value_type = value_type
        self.pointer_candidates: Optional[List[int]] = None
        self.inferior = gdb.selected_inferior()
        self.last_search_value: Optional[int] = None

        self._max_print_limit: int = 0

    @property
    def max_print_limit(self) -> int:
        """
        Retrieves the maximum number of search results to display for this variable.
        < 0 = unlimited
        :return:
        """
        return max(0, self._max_print_limit)

    @max_print_limit.setter
    def max_print_limit(self, value: int) -> None:
        self._max_print_limit = value

    def populate(self, target_value: Union[int, float]) -> int:
        """
        Initial populate
        :param target_value: initial values to search.
        :return:  Number of initial candidates
        """
        search_segments = CheatSession.discover_segments()
        if not search_segments:
            _logger.error(f"No segments found!")
            return 0

        if target_value is None:
            _logger.error(f"Target value not set!")
            return 0

        if self.pointer_candidates is None:
            byte_pattern = self.value_type.to_buffer(target_value)
            self.pointer_candidates = []
            _logger.info(f"Searching for byte pattern: {self.value_type.to_readable(target_value)}")

            with tqdm.tqdm(total=sum(map(len, search_segments)),
                           desc="Searching memory",
                           unit="bytes",
                           unit_scale=True,
                           unit_divisor=1024) as progress:
                for segment in search_segments:
                    search_start = segment.start
                    search_end = segment.end
                    progress.update(search_end - search_start)
                    while True:
                        search_length = search_end - search_start
                        if search_length <= 0:
                            break

                        try:
                            search_result = self.inferior.search_memory(search_start, search_length, byte_pattern)
                        except gdb.MemoryError as e:
                            _logger.error(f"Skipping unreadable segment {segment.start:016x}-{segment.end:016x}!", exc_info=e)
                            _logger.info("You may want to rediscover segments and try again.")
                            continue
                        except ValueError as e:
                            _logger.error(f"Skipping segment {segment.start:016x}-{segment.end:016x}!", exc_info=e)
                            continue

                        if search_result is None:
                            break
                        else:
                            _logger.debug(f"Found match at 0x{search_result:016x}")
                            self.pointer_candidates.append(int(search_result))
                        search_start = search_result + self.value_type.length_bytes
            _logger.info(f"Found {len(self.pointer_candidates)} memory pointer candidates")
            self.last_search_value = target_value
        else:
            _logger.error(f"Search session has already been populated. Skipping.")

        return len(self.pointer_candidates)

    def narrow(self, target_value: Optional[Union[int, float]] = None) -> int:
        """
        Narrow search - remove candidates with non-matching values.
        :param target_value: The value to match, or repeat last search if unspecified.
        :return: Number of candidates remaining.
        """
        if self.pointer_candidates is None:
            _logger.info(f"Populating initial candidates...")
            return self.populate(target_value)

        if len(self.pointer_candidates) == 0:
            _logger.info(f"No candidates remaining. You may want to reset and restart this search.")
            return 0

        if target_value is None:
            target_value = self.last_search_value

        if target_value is None:
            _logger.info(f"No search history yet! Please provide value.")
            return 0

        target_byte_pattern = self.value_type.to_buffer(target_value)
        _logger.info(f"Searching for byte pattern: {self.value_type.to_readable(target_byte_pattern)}")

        remaining_candidates: List[int] = []
        for candidate in tqdm.tqdm(self.pointer_candidates, desc="Narrowing down memory candidates", unit="items"):
            try:
                current_pattern = bytes(self.inferior.read_memory(candidate, self.value_type.length_bytes))
            except gdb.MemoryError:
                # This memory might have been remapped. Consider this candidate eliminated
                _logger.debug(f"Eliminating candidate 0x{candidate:016x}")
                continue

            if current_pattern == target_byte_pattern:
                _logger.debug(f"Keeping candidate 0x{candidate:016x}")
                remaining_candidates.append(candidate)
            else:
                _logger.debug(f"Eliminating candidate 0x{candidate:016x}")

        self.pointer_candidates = remaining_candidates
        if len(remaining_candidates) > 1:
            _logger.info(f"{len(remaining_candidates)} memory pointer candidates remaining.")
        elif len(remaining_candidates) == 1:
            _logger.info(
                f"Only 1 memory pointer candidate remaining. You may want to watch this value to confirm behavior.")
        elif len(remaining_candidates) == 0:
            _logger.info(f"No matching memory pointer candidates remaining.")

        self.last_search_value = target_value
        return len(remaining_candidates)

    def reset(self):
        self.pointer_candidates = None
        self.inferior = gdb.selected_inferior()
        self.last_search_value = None

    def search_state(self) -> List[Tuple[int, Union[int, float], str]]:
        """
        Return a list of current candidate addresses and their values.
        :return: list of candidates address, their current values and hexadecimal representation.
        """
        if self.pointer_candidates is None:
            return []

        current_values: List[Tuple[int, Union[int, float], str]] = []

        for candidate in self.pointer_candidates:
            buffer = bytes(self.inferior.read_memory(candidate, self.value_type.length_bytes))
            value = self.value_type.from_buffer(buffer)
            buffer_string = self.value_type.to_readable(value)
            current_values.append((candidate, value, buffer_string))

        return current_values

    def summarize(self, from_tty: bool) -> None:
        """
        Print a summary of the current search state.
        :param from_tty:
        :return:
        """
        print("=== Current search ===")
        populated = self.is_populated()
        search_type = self.value_type
        last_search = self.last_search_value
        print(f"Target variable type     {search_type}")
        print(f"Last value searched      {last_search}")
        if populated:
            print(f"Search state")
            search_state = _session.current_search.search_state()
            if from_tty and len(search_state) > self.max_print_limit > 0:
                print(f"  {len(search_state)} candidate variables found. Narrow further to show values.")
            else:
                for index, candidate in enumerate(search_state):
                    address, value, hex_string = candidate
                    print(f"[{index:>4}] 0x{address:016x} {value:>16} {hex_string}")
        else:
            print(f"Search state             Unpopulated")

    def define_variable(self, name: str, address: Optional[int] = None) -> Optional[VariableDefinition]:
        """
        Produce a variable definition from the given name.
        :param name:     The name of the variable to create.
        :param address:  The address of the variable to define.
                         Choose from current search results. Can be omitted if the search only has 1 result.
        :return: The variable definition.
        """
        if self.pointer_candidates is None:
            _logger.error("Please populate this search first.")
            return None

        if len(self.pointer_candidates) > 1 and address is None:
            _logger.error("More than 1 results found. Please choose one to create variable.")
            return None
        elif len(self.pointer_candidates) == 0:
            _logger.error("No candidates remaining. Please reset and restart this search with different values.")
            return None

        if len(self.pointer_candidates) == 1:
            address = self.pointer_candidates[0]
        elif address not in self.pointer_candidates:
            _logger.error(f"Requested address 0x{address:016x} is not in the search results.")
            self.summarize(from_tty=True)
            return None

        return VariableDefinition(name, self.value_type, address)

    def is_populated(self) -> bool:
        return self.pointer_candidates is not None

    def __len__(self) -> int:
        return len(self.pointer_candidates)


class CheatSession:
    """ Cheat global session state """

    def __init__(self):
        self.variables: List[VariableDefinition] = []
        self.watchpoints: Dict[VariableDefinition, LockedValueWatchpoint] = dict()
        self.current_search: Optional[SearchSession] = None

        _logger.info("Initializing cheat session.")

    @staticmethod
    def discover_segments() -> List[MemorySegment]:
        target_pid = gdb.selected_inferior().pid
        if not target_pid:
            _logger.error("No target PID.")
            return []

        process_segments = []
        with open(f"/proc/{target_pid}/maps", "r") as procfs_maps:
            for line in procfs_maps.readlines():
                segment = MemorySegment.from_proc_pid_map(line)
                process_segments.append(segment)

        eligible_segments = [segment for segment in process_segments if
                             not segment.file_backed and segment.writable and segment.readable and len(segment) > 0]

        _logger.info("Found {} segments.".format(len(process_segments)))
        _logger.info("Found {} segments containing runtime data.".format(len(eligible_segments)))

        return eligible_segments

    def variable_lock_create(self, variable: VariableDefinition, value: Union[int]):
        if variable in self.watchpoints.keys():
            old_watchpoint = self.watchpoints.pop(variable)
            old_watchpoint.delete()
            _logger.info(f"Replacing existing watchpoint {old_watchpoint}={old_watchpoint.value}")

        _logger.info(f"Creating new watchpoint {variable} with value 0x{value:08x}.")
        self.watchpoints[variable] = LockedValueWatchpoint(variable, value)

    def variable_lock_enable(self, variable: VariableDefinition):
        watchpoint = self.watchpoints.get(variable, None)
        if watchpoint is None:
            _logger.error(f"Variable {variable.name} is not locked by this cheat session.")
            return

        self.watchpoints[variable].enabled = True
        _logger.info(f"Watchpoint {variable}={watchpoint.value} enabled.")

    def variable_lock_disable(self, variable: VariableDefinition):
        watchpoint = self.watchpoints.get(variable, None)
        if watchpoint is None:
            _logger.error(f"Variable {variable.name} is not locked by this cheat session.")
            return

        self.watchpoints[variable].enabled = False
        _logger.info(f"Watchpoint {variable}={watchpoint.value} enabled.")

    def variable_lock_delete(self, variable: VariableDefinition):
        if variable in self.watchpoints.keys():
            old_watchpoint = self.watchpoints.pop(variable)
            old_watchpoint.delete()

            _logger.info(f"Watchpoint {variable}={old_watchpoint.value} deleted.")
        else:
            _logger.error(f"Variable {variable.name} is not locked by this cheat session.")

    def cleanup(self):
        _logger.info("Cleaning up cheat session.")
        for watchpoint in self.watchpoints.values():
            watchpoint.delete()
        self.watchpoints = []

    def summarize_variables(self) -> None:
        print("=== Variables ===")
        for index, v in enumerate(self.variables):
            if not v.valid:
                continue
            read_result = v.get()
            if read_result is None:
                print(
                    f"[{index:>3}]  0x{v.address:016x} {v.name:<20} {v.value_type.short_hand:<4} READ FAILURE")
                continue
            else:
                value, buffer_string = read_result
                print(
                    f"[{index:>3}]  0x{v.address:016x} {v.name:<20} {v.value_type.short_hand:<4} {value:>16} {buffer_string}")

    def summarize_watchpoints(self) -> None:
        print("=== Variable Lock Watchpoints ===")
        for v, watchpoint in self.watchpoints.items():
            active = "[*]" if watchpoint.enabled else "[ ]"
            print(f"{active} 0x{v.address:016x} {v.name:<20} {watchpoint.value:>16}")


# Global State ================================================================

_session: Optional[CheatSession] = None


# GDB Prefix Commands =========================================================

class PrefixCheat(gdb.Command):
    """
    Cheat engine top level prefix

    Usage: cheat <subcommand>
    """

    def __init__(self):
        super(PrefixCheat, self).__init__("cheat", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatSession(gdb.Command):
    """
    Manage session wide settings

    Usage: cheat session <subcommand>
    """

    def __init__(self):
        super(PrefixCheatSession, self).__init__("cheat session", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatSearch(gdb.Command):
    """
    Control memory search

    Usage: cheat search <subcommand>
    """

    def __init__(self):
        super(PrefixCheatSearch, self).__init__("cheat search", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatLock(gdb.Command):
    """
    Control memory content locking at specific addresses

    Usage: cheat session <subcommand>
    """

    def __init__(self):
        super(PrefixCheatLock, self).__init__("cheat lock", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


class PrefixCheatVariable(gdb.Command):
    """
    Manage variable definitions

    Usage: cheat variable <subcommand>
    """

    def __init__(self):
        super(PrefixCheatVariable, self).__init__("cheat variable", gdb.COMMAND_USER, gdb.COMPLETE_COMMAND, True)


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
            gdb.execute(f"handle {signal} nostop noprint noignore", from_tty=from_tty)


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
        if len(argv) != 1:
            _logger.error("Usage: cheat_search_populate <initial value to search>")
            return

        try:
            if _session.current_search.value_type.is_integral:
                target_value = int(argv[0], 0)
            else:
                target_value = float(argv[0])

            _session.current_search.populate(target_value)
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
            "--poll", type=int, default=0, help="Poll this many times periodically while running.", dest="poll"
        )
        self.argument_parser.add_argument(
            "--interval", type=int, default=5, help="Polling interval in seconds. Defaults to 5.", dest="interval"
        )
        self.argument_parser.add_argument(
            "search_value", type=str, help="Value to search for.", nargs='?', default=None
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
        except Exception as e:
            _logger.error(f"Argument parsing failed: {e}", exc_info=None)
            return

        if parsed_args.poll < 0:
            _logger.error(f"Polling counts must be positive: {parsed_args.poll}")
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
                    _session.current_search.narrow(search_value)
                return

            # Polling mode
            with InferiorState(gdb.selected_inferior(), "run"):
                for polled in tqdm.tqdm(range(parsed_args.poll), desc="Polling...", unit="attempt"):
                    with InferiorState(gdb.selected_inferior(), "pause"):
                        _session.current_search.narrow(search_value)

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

    @staticmethod
    def summarize(from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        if _session.current_search is None:
            _logger.error("No variable search in progress.")
            return

        _session.current_search.summarize(from_tty)

    def invoke(self, argument: str, from_tty: bool) -> None:
        return CommandCheatSearchSummary.summarize(from_tty)


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
            _logger.error("Usage: cheat_search_variable <variable name> [search result index, default 0]")
            return

        index = 0 if len(argv) > 1 else int(argv[1])

        # Actual work
        try:
            candidates = _session.current_search.search_state()
            if index >= len(candidates):
                _logger.error("Invalid search result index.")
                return

            address = candidates[index][0]
            variable = _session.current_search.define_variable(argv[0], address)

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
            _logger.error("Usage: cheat_variable_create <name> <type> <address>")
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
                _session.variables.append(VariableDefinition(name, value_type, address))

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
                _logger.error(f"Variable {variable} is in-use by one of the watchpoints and cannot be deleted.")
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

# Create session for convenience
gdb.execute("cheat session create")
