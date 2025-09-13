#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

# GDB Cheats - Core types

import logging
import struct
import sys
from contextlib import AbstractContextManager
from enum import Enum
from time import sleep
from typing import Optional, List, Dict, Tuple, Literal, Union

import gdb

from cheats_search import GdbBuiltInSearch, MemorySearchImpl, MultiProcessingSearchImpl

_logger = logging.getLogger("core")


class InferiorState(AbstractContextManager):
    """
    Force inferior to enter a specified running state and restore upon exit
    """

    _logger = logging.getLogger("inferior")

    def __init__(self, inferior: gdb.Inferior, state: Literal["run", "pause"]):
        self.inferior = inferior
        self.should_run = state == "run"

    @staticmethod
    def _run():
        InferiorState._logger.info("Continuing inferior execution")
        gdb.execute("continue &")

    @staticmethod
    def _stop():
        InferiorState._logger.info("Pausing inferior execution")
        gdb.execute("interrupt -a")
        sleep(0.1)

    def __enter__(self) -> None:
        if self.inferior.pid == 0:
            raise ValueError("Inferior is not running.")

        self.was_running = any(t.is_running()
                               for t in self.inferior.threads() if t.is_valid())
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
            raise ValueError(
                f"Buffer too small! Need {self.length_bytes} bytes to encode {self}, only have {len(buffer)} bytes.")

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
    """
    Represents a variable living in the program's memory space.
    """

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
        process.write_memory(self.address, buffer,
                             self.value_type.length_bytes)

    def get(self) -> Optional[Tuple[Union[int, float], str]]:
        """ Get value from buffer """
        process = gdb.selected_inferior()
        try:
            buffer = bytes(process.read_memory(
                self.address, self.value_type.length_bytes))
        except gdb.MemoryError:
            _logger.error(
                f"Failed to get value from variable {self.name} at 0x{self.address:016x}")
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
    """
    Actual watchpoint implementation: locks value on change
    """
    _logger = logging.getLogger("watchpoint")

    def __init__(self, variable: VariableDefinition, value: Union[int, float]):
        super().__init__(variable.format_spec(), gdb.BP_WATCHPOINT, gdb.WP_WRITE, True)
        self.variable = variable
        self.value = value

    def stop(self):
        """Upon trigger force value overwrite"""
        self.variable.set(self.value)
        _logger.debug(f"Watchpoint {self.variable.name}={self.value} fired.")

    def get_variable(self) -> VariableDefinition:
        return self.variable


class MemorySegmentPermission:
    """
    Bit fields for segment permission flags
    """

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
    """
    Represents a segment in the memory space.
    """

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
        """
        Parse a memory segment from a proc pid map.
        :param line: line from proc fs pid map
        :return: Parsed memory segment
        """
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
        self.candidates: Optional[List[int]] = None
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

    def populate(
            self,
            target_value: Union[int, float],
            search_impl: Literal["gdb", "mp"] = "gdb"
    ) -> int:
        """
        Initial populate
        :param target_value: Initial values to search.
        :param search_impl:  Search implementation.
        :return:  Number of initial candidates
        """

        if search_impl == "gdb":
            _search_impl: MemorySearchImpl = GdbBuiltInSearch(self.inferior)
        elif search_impl == "mp":
            _search_impl: MemorySearchImpl = MultiProcessingSearchImpl(self.inferior)
        else:
            raise ValueError(f"Unknown search implementation: {search_impl}")

        search_segments = CheatSession.discover_segments()

        if not search_segments:
            _logger.error(f"No segments found!")
            return 0

        if target_value is None:
            _logger.error(f"Target value not set!")
            return 0

        if self.candidates is None:
            byte_pattern = self.value_type.to_buffer(target_value)
            _logger.info(
                f"Searching for byte pattern: {self.value_type.to_readable(target_value)}")

            search_areas = [(segment.start, segment.end) for segment in search_segments]
            self.candidates = _search_impl.exact(search_areas, byte_pattern)

            _logger.info(
                f"Found {len(self.candidates)} memory pointer candidates")
            self.last_search_value = target_value
        else:
            _logger.error(
                f"Search session has already been populated. Skipping.")

        return len(self.candidates)

    def narrow(
            self,
            target_value: Optional[Union[int, float]] = None,
            search_impl: Literal["gdb", "mp"] = "gdb",
    ) -> int:
        """
        Narrow search - remove candidates with non-matching values.
        :param target_value: The value to match, or repeat last search if unspecified.
        :param search_impl:  Search implementation.
        :return: Number of candidates remaining.
        """
        if self.candidates is None:
            _logger.info(f"Populating initial candidates...")
            return self.populate(target_value, search_impl)

        if search_impl == "gdb":
            _search_impl: MemorySearchImpl = GdbBuiltInSearch(self.inferior)
        elif search_impl == "mp":
            _search_impl: MemorySearchImpl = MultiProcessingSearchImpl(self.inferior)
        else:
            raise ValueError(f"Unknown search implementation: {search_impl}")

        if len(self.candidates) == 0:
            _logger.info(
                f"No candidates remaining. You may want to reset and restart this search.")
            return 0

        if target_value is None:
            target_value = self.last_search_value

        if target_value is None:
            _logger.info(f"No search history yet! Please provide value.")
            return 0

        target_byte_pattern = self.value_type.to_buffer(target_value)
        _logger.info(
            f"Searching for byte pattern: {self.value_type.to_readable(target_byte_pattern)}")

        remaining_candidates: List[int] = _search_impl.narrow_exact(self.candidates, target_byte_pattern)

        self.candidates = remaining_candidates
        if len(remaining_candidates) > 1:
            _logger.info(
                f"{len(remaining_candidates)} memory pointer candidates remaining.")
        elif len(remaining_candidates) == 1:
            _logger.info(
                f"Only 1 memory pointer candidate remaining. You may want to watch this value to confirm behavior.")
        elif len(remaining_candidates) == 0:
            _logger.info(f"No matching memory pointer candidates remaining.")

        self.last_search_value = target_value
        return len(remaining_candidates)

    def reset(self) -> None:
        self.candidates = None
        self.inferior = gdb.selected_inferior()
        self.last_search_value = None

    def search_state(self) -> List[Tuple[int, Union[int, float], str]]:
        """
        Return a list of current candidate addresses and their values.
        :return: list of candidates address, their current values and hexadecimal representation.
        """
        if self.candidates is None:
            return []

        current_values: List[Tuple[int, Union[int, float], str]] = []

        for candidate in self.candidates:
            buffer = bytes(self.inferior.read_memory(
                candidate, self.value_type.length_bytes))
            value = self.value_type.from_buffer(buffer)
            buffer_string = self.value_type.to_readable(value)
            current_values.append((candidate, value, buffer_string))

        return current_values

    def summarize(self, from_tty: bool, print_limit: Optional[int] = None) -> None:
        """
        Print a summary of the current search state.
        :param from_tty:    Whether the function is invoked from tty or not.
        :param print_limit: Don't print if the number of candidates is above this limit.
        :return:
        """
        _print_limit = print_limit if print_limit is not None else self.max_print_limit


        print("=== Current search ===")
        populated = self.is_populated()
        search_type = self.value_type
        last_search = self.last_search_value
        print(f"Target variable type     {search_type}")
        print(f"Last value searched      {last_search}")
        if populated:
            print(f"Search state")
            search_state = self.search_state()
            if from_tty and len(search_state) > _print_limit > 0:
                print(
                    f"  {len(search_state)} candidate variables found. Narrow further to show values.")
            else:
                for index, candidate in enumerate(search_state):
                    address, value, hex_string = candidate
                    print(
                        f"[{index:>4}] 0x{address:016x} {value:>16} {hex_string}")
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
        if self.candidates is None:
            _logger.error("Please populate this search first.")
            return None

        if len(self.candidates) > 1 and address is None:
            _logger.error(
                "More than 1 results found. Please choose one to create variable.")
            return None
        elif len(self.candidates) == 0:
            _logger.error(
                "No candidates remaining. Please reset and restart this search with different values.")
            return None

        if len(self.candidates) == 1:
            address = self.candidates[0]
        elif address not in self.candidates:
            _logger.error(
                f"Requested address 0x{address:016x} is not in the search results.")
            self.summarize(from_tty=True)
            return None

        return VariableDefinition(name, self.value_type, address)

    def is_populated(self) -> bool:
        return self.candidates is not None

    def __len__(self) -> int:
        return len(self.candidates)


class CheatSession:
    """ Cheat global session state """

    def __init__(self):
        self.variables: List[VariableDefinition] = []
        self.watchpoints: Dict[VariableDefinition,
                               LockedValueWatchpoint] = dict()
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
        _logger.info("Found {} segments containing runtime data.".format(
            len(eligible_segments)))

        return eligible_segments

    def variable_lock_create(self, variable: VariableDefinition, value: Union[int]) -> None:
        if variable in self.watchpoints.keys():
            old_watchpoint = self.watchpoints.pop(variable)
            old_watchpoint.delete()
            _logger.info(
                f"Replacing existing watchpoint {old_watchpoint}={old_watchpoint.value}")

        _logger.info(
            f"Creating new watchpoint {variable} with value 0x{value:08x}.")
        self.watchpoints[variable] = LockedValueWatchpoint(variable, value)

    def variable_lock_enable(self, variable: VariableDefinition) -> None:
        watchpoint = self.watchpoints.get(variable, None)
        if watchpoint is None:
            _logger.error(
                f"Variable {variable.name} is not locked by this cheat session.")
            return

        self.watchpoints[variable].enabled = True
        _logger.info(f"Watchpoint {variable}={watchpoint.value} enabled.")

    def variable_lock_disable(self, variable: VariableDefinition) -> None:
        watchpoint = self.watchpoints.get(variable, None)
        if watchpoint is None:
            _logger.error(
                f"Variable {variable.name} is not locked by this cheat session.")
            return

        self.watchpoints[variable].enabled = False
        _logger.info(f"Watchpoint {variable}={watchpoint.value} enabled.")

    def variable_lock_delete(self, variable: VariableDefinition) -> None:
        if variable in self.watchpoints.keys():
            old_watchpoint = self.watchpoints.pop(variable)
            old_watchpoint.delete()

            _logger.info(
                f"Watchpoint {variable}={old_watchpoint.value} deleted.")
        else:
            _logger.error(
                f"Variable {variable.name} is not locked by this cheat session.")

    def cleanup(self) -> None:
        _logger.info("Cleaning up cheat session.")
        for watchpoint in self.watchpoints.values():
            watchpoint.delete()
        self.watchpoints = {}

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


if __name__ == "__main__":
    print("You should not source this file directly. Use top level cheats.py instead.", file=sys.stderr)
