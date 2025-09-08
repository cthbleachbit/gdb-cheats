#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0

import logging

_logger = logging.getLogger("cheats")
logging.basicConfig(level=logging.INFO)

import gdb
import tqdm
from typing import Optional, List, Collection, Set, Dict, Tuple
from enum import Enum


def bytes_to_readable(buffer: bytes) -> str:
    return " ".join([f"{b:02x}" for b in buffer])


class ValueType(str, Enum):
    I8 = "char",
    I16 = "short",
    I32 = "int",
    I64 = "long",
    U8 = "unsigned char",
    U16 = "unsigned short",
    U32 = "unsigned int",
    U64 = "unsigned long",

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
        elif self == ValueType.I32 or self == ValueType.U32:
            return 4
        elif self == ValueType.I64 or self == ValueType.U64:
            return 8

    @property
    def signed(self) -> bool:
        """ Return True if the value is signed. """
        if self == ValueType.I8 or self == ValueType.I16 or self == ValueType.I32 or self == ValueType.I64:
            return True
        else:
            return False

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
        }

        return lookup_table[self]


class VariableDefinition:
    def __init__(self, name: str, value_type: ValueType, address: int):
        self.name = name
        self.value_type = value_type
        self.address = address
        self.valid = True

    def format_spec(self) -> str:
        """ Format to gdb acceptable spec """
        return self.value_type.format_spec(self.address)

    def set(self, value: int) -> None:
        """ Set value to buffer """
        process = gdb.selected_inferior()
        buffer = value.to_bytes(length=self.value_type.length_bytes, byteorder="little")
        process.write_memory(self.address, buffer, self.value_type.length_bytes)

    def get(self) -> Optional[Tuple[int, str]]:
        """ Get value from buffer """
        process = gdb.selected_inferior()
        try:
            buffer = bytes(process.read_memory(self.address, self.value_type.length_bytes))
        except gdb.MemoryError:
            _logger.error(f"Failed to get value from variable {self.name} at 0x{self.address:016x}")
            return None

        buffer_string = bytes_to_readable(buffer)
        value = int.from_bytes(buffer, byteorder="little", signed=self.value_type.signed)
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
    def __init__(self, variable: VariableDefinition, value: int):
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

    def is_file_backed(self) -> bool:
        return self.pathname.startswith("/") and self.offset > 0

    def is_writable(self) -> bool:
        return self.permissions.w

    def is_readable(self) -> bool:
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
        self.pointer_candidates: Optional[Set[int]] = None
        self.inferior = gdb.selected_inferior()
        self.last_search_value: Optional[int] = None

    def populate(self, target_value: int, search_segments: Collection[MemorySegment]) -> int:
        """
        Initial populate
        :param target_value: initial values to search.
        :param search_segments:    Look for the value in these MemorySegments.
        :return:  Number of initial candidates
        """
        if self.pointer_candidates is None:
            byte_pattern = target_value.to_bytes(self.value_type.length_bytes, byteorder="little")
            self.pointer_candidates: Set[int] = set()
            _logger.info(f"Searching for byte pattern: {bytes_to_readable(byte_pattern)}")

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
                        search_result = self.inferior.search_memory(search_start, search_length, byte_pattern)
                        if search_result is None:
                            break
                        else:
                            _logger.debug(f"Found match at 0x{search_result:016x}")
                            self.pointer_candidates.add(int(search_result))
                        search_start = search_result + self.value_type.length_bytes
            _logger.info(f"Found {len(self.pointer_candidates)} memory pointer candidates")
            self.last_search_value = target_value
        else:
            _logger.error(f"Search session has already been populated. Skipping.")

        return len(self.pointer_candidates)

    def narrow(self, target_value: Optional[int] = None) -> int:
        """
        Narrow search - remove candidates with non-matching values.
        :param target_value: The value to match, or repeat last search if unspecified.
        :return: Number of candidates remaining.
        """
        if self.pointer_candidates is None:
            _logger.error(f"Please populate this search first.")
            return 0
        if len(self.pointer_candidates) == 0:
            _logger.info(f"No candidates remaining. You may want to reset and restart this search.")
            return 0

        if target_value is None:
            target_value = self.last_search_value

        target_byte_pattern = target_value.to_bytes(self.value_type.length_bytes, byteorder="little")
        _logger.info(f"Searching for byte pattern: {bytes_to_readable(target_byte_pattern)}")

        remaining_candidates: Set[int] = set()
        for candidate in tqdm.tqdm(self.pointer_candidates, desc="Narrowing down memory candidates", unit="items"):
            try:
                current_pattern = bytes(self.inferior.read_memory(candidate, self.value_type.length_bytes))
            except gdb.MemoryError:
                # This memory might have been remapped. Consider this candidate eliminated
                _logger.debug(f"Eliminating candidate 0x{candidate:016x}")
                continue

            if current_pattern == target_byte_pattern:
                _logger.debug(f"Keeping candidate 0x{candidate:016x}")
                remaining_candidates.add(candidate)
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

    def search_state(self) -> Dict[int, Tuple[int, str]]:
        """
        Return a summary of the current search session, and current values of the candidate pointers.
        :return: remaining candidates address, their current values and hexadecimal representation.
        """
        if self.pointer_candidates is None:
            return {}

        current_values: Dict[int, Tuple[int, str]] = dict()

        for candidate in self.pointer_candidates:
            buffer = bytes(self.inferior.read_memory(candidate, self.value_type.length_bytes))
            buffer_string = bytes_to_readable(buffer)
            value = int.from_bytes(buffer, byteorder="little", signed=self.value_type.signed)
            current_values[candidate] = (value, buffer_string)

        return current_values

    def define_variable(self, name: str) -> Optional[VariableDefinition]:
        """
        Produce a variable definition from the given name if there's only 1 pointer left.
        :param name: The name of the variable to create.
        :return: The variable definition.
        """
        if len(self.pointer_candidates) != 1:
            _logger.error("Can only define variables with search narrowed down to exactly 1 pointer.")
            return None

        candidate = self.pointer_candidates.pop()
        return VariableDefinition(name, self.value_type, candidate)

    def is_populated(self) -> bool:
        return self.pointer_candidates is not None

    def __len__(self) -> int:
        return len(self.pointer_candidates)


class CheatSession:
    """ Cheat global session state """

    def __init__(self):
        self.process_segments: List[MemorySegment] = []
        self.eligible_segments: List[MemorySegment] = []
        self.variables: List[VariableDefinition] = []
        self.watchpoints: Dict[VariableDefinition, LockedValueWatchpoint] = dict()
        self.current_search: Optional[SearchSession] = None

        _logger.info("Initializing cheat session.")

    def discover_segments(self):
        target_pid = gdb.selected_inferior().pid
        self.process_segments = []
        self.eligible_segments = []
        with open(f"/proc/{target_pid}/maps", "r") as procfs_maps:
            for line in procfs_maps.readlines():
                segment = MemorySegment.from_proc_pid_map(line)
                self.process_segments.append(segment)

        self.eligible_segments = [segment for segment in self.process_segments if
                                  not segment.is_file_backed() and segment.is_writable() and segment.is_readable()]

        _logger.info("Found {} segments.".format(len(self.process_segments)))
        _logger.info("Found {} segments containing runtime data.".format(len(self.eligible_segments)))

    def variable_lock_create(self, variable: VariableDefinition, value: int):
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
                    f"[{index:>3}]  0x{v.address:016x} {v.name:<20} {v.value_type.short_hand} READ FAILURE")
                continue
            else:
                value, buffer_string = read_result
                print(
                    f"[{index:>3}]  0x{v.address:016x} {v.name:<20} {v.value_type.short_hand} {value:>16} {buffer_string}")

    def summarize_watchpoints(self) -> None:
        print("=== Variable Lock Watchpoints ===")
        for variable, watchpoint in self.watchpoints.items():
            active = "[*]" if watchpoint.enabled else "[ ]"
            print(f"{active} 0x{variable.address:016x} {variable.name:<20} {watchpoint.value:>16}")


# ============================= GDB Commands ===================================

_session: Optional[CheatSession] = None


class CheatSessionCreate(gdb.Command):
    """
    Create a new cheat session.

    Usage: cheat_create_session
    """

    def __init__(self):
        super(CheatSessionCreate, self).__init__(
            "cheat_session_create",
            gdb.COMMAND_USER,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        self.dont_repeat()

        if _session is not None:
            _session.cleanup()

        _session = CheatSession()
        _session.discover_segments()

        # Also do environmental setup
        # Unity games use SIGPWR, SIGXCPU, SIGUSR1, SIGUSR2 for some reason.
        # Make sure GDB don't stop on these signals and pass them to programs unchanged instead.
        for signal in ["SIGPWR", "SIGXCPU", "SIGUSR1", "SIGUSR2"]:
            gdb.execute(f"handle {signal} nostop noprint noignore", from_tty=from_tty)


class CheatSessionSummary(gdb.Command):
    """
    Print a summary of the current cheat session.
    This includes all variables and watchpoints defined in this cheat session and current search (if one is in progress).

    Usage: cheat_summary_session
    """

    SEARCH_STATE_PRINT_MAX = 100

    def __init__(self):
        super(CheatSessionSummary, self).__init__(
            "cheat_session_summary",
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
        CheatSearchSummary.summarize(from_tty)


class CheatSessionDelete(gdb.Command):
    """
    Clean up current cheat session.
    Usage: cheat_delete_session
    """

    def __init__(self):
        super(CheatSessionDelete, self).__init__(
            "cheat_session_delete",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")

        _session.cleanup()
        _session = None


class CheatSearchCreate(gdb.Command):
    """
    Start a new cheat search session.
    Usage: cheat_search <target variable type>
    """

    def __init__(self):
        super(CheatSearchCreate, self).__init__(
            "cheat_search_create",
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


class CheatSearchPopulate(gdb.Command):
    """
    Populate a cheat search session.
    Usage: cheat_search_populate <initial value to search>
    """

    def __init__(self):
        super(CheatSearchPopulate, self).__init__(
            "cheat_search_populate",
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
            _logger.error("Invalid number of arguments. Pass exactly 1 argument for value to search.")
            return

        target_value = int(argv[0], 0)
        _session.current_search.populate(target_value, _session.eligible_segments)


class CheatSearchNarrow(gdb.Command):
    """
    Narrow down a cheat search session.
    Usage: cheat_search_narrow <value to search>
    """

    def __init__(self):
        super(CheatSearchNarrow, self).__init__(
            "cheat_search_narrow",
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
        if len(argv) < 1:
            target_value = None
        else:
            target_value = int(argv[0], 0)

        _session.current_search.narrow(target_value)


class CheatSearchSummary(gdb.Command):
    """
    Print a summary of the current cheat session.
    Usage: cheat_summary_session
    """

    def __init__(self):
        super(CheatSearchSummary, self).__init__(
            "cheat_search_summary",
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
            print("No variable search in progress.")
        else:
            print("=== Current search ===")
            populated = _session.current_search.is_populated()
            search_type = _session.current_search.value_type
            last_search = _session.current_search.last_search_value
            print(f"Target variable type     {search_type}")
            print(f"Last value searched      {last_search}")
            if populated:
                print(f"Search state")
                search_state = _session.current_search.search_state()
                if from_tty and len(search_state) > CheatSessionSummary.SEARCH_STATE_PRINT_MAX:
                    print(f"  {len(search_state)} candidate variables found. Narrow further to show values.")
                else:
                    for address in search_state.keys():
                        value, hex_string = search_state[address]
                        print(f"  0x{address:016x}  {value:>16}   {hex_string}")
            else:
                print(f"Search state             Unpopulated")

    def invoke(self, argument: str, from_tty: bool) -> None:
        return CheatSearchSummary.summarize(from_tty)


class CheatSearchDefineVariable(gdb.Command):
    """
    Define a cheat variable and add it to the global session state.
    Usage: cheat_search_variable <variable name>
    """

    def __init__(self):
        super(CheatSearchDefineVariable, self).__init__(
            "cheat_search_define_variable",
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

        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error("Invalid number of arguments. Pass exactly 1 argument for name of variable to define.")
            return

        variable = _session.current_search.define_variable(argv[0])
        if variable is not None:
            _session.variables.append(variable)
            _logger.info(f"New variable defined at index = {len(_session.variables) - 1}.")
            _session.summarize_variables()


class CheatSearchReset(gdb.Command):
    """
    Define a cheat variable and add it to the global session state.
    Usage: cheat_search_reset <variable name>
    """

    def __init__(self):
        super(CheatSearchReset, self).__init__(
            "cheat_search_reset",
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


class CheatLockCreate(gdb.Command):
    """
    Create a new lock that locks a defined variable to a defined value.
    Usage: cheat_lock_create <variable index> <locked value>
    """

    def __init__(self):
        super(CheatLockCreate, self).__init__(
            "cheat_lock_create",
            gdb.COMMAND_DATA,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        argv = gdb.string_to_argv(argument)
        if len(argv) < 2:
            _logger.error(
                "Invalid number of arguments. Pass exactly 2 argument for variable def index and lock-in value.")
            return

        variable_index = int(argv[0], 0)
        locked_value = int(argv[1], 0)

        if variable_index > len(_session.variables):
            _logger.error("Invalid variable index.")
            return
        variable = _session.variables[variable_index]

        if not variable.valid:
            _logger.error("Invalid variable.")

        _session.variable_lock_create(variable, locked_value)
        _session.summarize_watchpoints()


class CheatLockEnable(gdb.Command):
    """
    Enable a created lock on a defined variable.
    Usage: cheat_lock_enable <variable index>
    """

    def __init__(self):
        super(CheatLockEnable, self).__init__(
            "cheat_lock_enable",
            gdb.COMMAND_DATA,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error(
                "Invalid number of arguments. Pass exactly 1 argument for variable def index.")
            return

        variable_index = int(argv[0], 0)

        if variable_index > len(_session.variables):
            _logger.error("Invalid variable index.")
            return
        variable = _session.variables[variable_index]

        if not variable.valid:
            _logger.error("Invalid variable.")

        _session.variable_lock_enable(variable)
        _session.summarize_watchpoints()


class CheatLockDisable(gdb.Command):
    """
    Enable a created lock on a defined variable.
    Usage: cheat_lock_enable <variable index>
    """

    def __init__(self):
        super(CheatLockDisable, self).__init__(
            "cheat_lock_disable",
            gdb.COMMAND_DATA,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error(
                "Invalid number of arguments. Pass exactly 1 argument for variable def index.")
            return

        variable_index = int(argv[0], 0)

        if variable_index > len(_session.variables):
            _logger.error("Invalid variable index.")
            return
        variable = _session.variables[variable_index]

        if not variable.valid:
            _logger.error("Invalid variable.")

        _session.variable_lock_disable(variable)
        _session.summarize_watchpoints()


class CheatLockDelete(gdb.Command):
    """
    Delete a created lock on a defined variable.
    Usage: cheat_lock_delete <variable index>
    """

    def __init__(self):
        super(CheatLockDelete, self).__init__(
            "cheat_lock_delete",
            gdb.COMMAND_DATA,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        argv = gdb.string_to_argv(argument)
        if len(argv) < 1:
            _logger.error(
                "Invalid number of arguments. Pass exactly 1 argument for variable def index."
            )
            return

        variable_index = int(argv[0], 0)

        if variable_index > len(_session.variables):
            _logger.error("Invalid variable index.")
            return
        variable = _session.variables[variable_index]

        if not variable.valid:
            _logger.error("Invalid variable.")

        _session.variable_lock_delete(variable)
        _session.summarize_watchpoints()


class CheatVariableCreate(gdb.Command):
    """
    Manually define a new variable.
    Usage: cheat_variable_create <name> <type> <address>
    """

    def __init__(self):
        super(CheatVariableCreate, self).__init__(
            "cheat_variable_create",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

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

        if address in [v.address for v in _session.variables if v.valid]:
            _logger.error(f"Address {address} already exists.")
        else:
            _session.variables.append(VariableDefinition(name, value_type, address))

        _session.summarize_variables()


class CheatVariableSet(gdb.Command):
    """
    Set value for variable.
    Usage: cheat_variable_set <index> <value>
    """

    def __init__(self):
        super(CheatVariableSet, self).__init__(
            "cheat_variable_set",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        argv = gdb.string_to_argv(argument)
        if len(argv) != 2:
            _logger.error("Usage: cheat_variable_set <index> <value>")
            return
        index = int(argv[0], 0)
        value = int(argv[1], 0)

        if index > len(_session.variables):
            _logger.error("Invalid variable index.")
            return

        variable = _session.variables[index]
        if not variable.valid:
            _logger.error("Invalid variable.")
            _session.summarize_variables()
            return
        if variable in _session.watchpoints.keys():
            _logger.error(f"Variable {variable} is in-use by one of the watchpoints. Update the watchpoint instead.")
            _session.summarize_watchpoints()
            return

        variable.set(value)
        _session.summarize_variables()


class CheatVariableDelete(gdb.Command):
    """
    Delete variable.
    Usage: cheat_variable_delete <index>
    """

    def __init__(self):
        super(CheatVariableDelete, self).__init__(
            "cheat_variable_delete",
            gdb.COMMAND_DATA,
            gdb.COMPLETE_NONE,
        )

    def invoke(self, argument: str, from_tty: bool) -> None:
        global _session
        if _session is None:
            _logger.error("No cheat session found.")
            return

        argv = gdb.string_to_argv(argument)
        if len(argv) != 1:
            _logger.error("Usage: cheat_variable_delete <index>")
            return
        index = int(argv[0], 0)

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


CheatSessionCreate()
CheatSessionSummary()
CheatSessionDelete()
CheatSearchCreate()
CheatSearchPopulate()
CheatSearchNarrow()
CheatSearchSummary()
CheatSearchDefineVariable()
CheatSearchReset()
CheatLockCreate()
CheatLockEnable()
CheatLockDisable()
CheatLockDelete()
CheatVariableCreate()
CheatVariableSet()
CheatVariableDelete()
