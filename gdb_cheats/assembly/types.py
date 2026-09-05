import abc
import copy
import enum
import itertools
import string
from collections import defaultdict
from dataclasses import dataclass, field
from tempfile import NamedTemporaryFile
from typing import Optional, List, Dict, Any, Tuple

from gdb_cheats.assembly.assembler import invoke_assembler, invoke_objdump_dump_symbol, invoke_objcopy_dump_section
from gdb_cheats.assembly.programs import assembler_native_machine, get_gnu_assembler


def _enforce_label(label: str):
    """
    Check label validity.
    """
    if set(label) - set(string.ascii_letters + string.digits + "_"):
        raise ValueError(f"Invalid label: {label}")


class EncodingOptions(str, enum.Enum):
    """
    Opcode / operands encoding options accepted by the GNU assembler.

    See https://sourceware.org/binutils/docs/as.html#Instruction-Naming
    """
    DISP_8 = "disp8"
    DISP_16 = "disp16"
    DISP_32 = "disp32"
    LOAD = "load"
    STORE = "store"
    VEX = "vex"
    VEX_3 = "vex3"
    EVEX = "evex"
    REX = "rex"
    REX_2 = "rex2"
    NO_IMM8S = "noimm8s"
    NO_OPTIMIZE = "nooptimize"

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"EncodingOptions.{self.name}"


class Machine(str, enum.Enum):
    """
    Supported machine architecture.
    String values taken from GNU assembler `cpu-type`.
    """
    AMD64 = "x86_64"
    AARCH64 = "aarch64"

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"Machine.{self.name}"


class InstrumentAction(abc.ABC):
    """
    An action to perform upon landing on this instruction.
    Action is performed BEFORE the instruction is executed.
    """

    @property
    def as_label(self) -> str:
        """
        Return the action as a label that can be consumed by the GNU assembler.
        """
        raise NotImplementedError()

    def __call__(self, gdb, variables: Dict[str, str]) -> None:
        """Perform the action."""
        raise NotImplementedError()

    def __repr__(self) -> str:
        raise NotImplementedError()

    def __str__(self) -> str:
        return repr(self)


@dataclass
class InstrumentBindVariable(InstrumentAction):
    """
    Indicate that the cheat engine should bind a search context variable
    to the value of a GDB expression.
    How this variable is interpreted depends on the game-specific driver.

    The variable name must be a valid assembly label.
    The expression is evaluated BEFORE the instruction is executed.
    """
    expression: str
    variable_name: str
    overwrite: bool = False

    def __post_init__(self):
        # require variable name to be a valid assembly label
        _enforce_label(self.variable_name)

    @property
    def as_label(self) -> str:
        return f"bind_variable_{self.variable_name}"

    def __call__(self, gdb, variables: Dict[str, Any]) -> None:
        """
        Perform the action.
        """
        value = gdb.parse_and_eval(self.expression)

        if self.overwrite or self.variable_name not in variables.keys():
            variables[self.variable_name] = value

    def __repr__(self) -> str:
        return f"InstrumentBindVariable(expression={repr(self.expression)}, variable_name={repr(self.variable_name)})"

    def __str__(self) -> str:
        return repr(self)

    def __deepcopy__(self, memo):
        return InstrumentBindVariable(
            expression=copy.deepcopy(self.expression, memo),
            variable_name=copy.deepcopy(self.variable_name, memo),
            overwrite=self.overwrite
        )


@dataclass
class Instruction:
    """
    An instruction in assembly in att format.
    During search, the cheat engine will search for instructions in assembled binary form.

    Fields:
    - assembly: The assembly instruction in AT&T format.
    - encoding: Optional encoding options for the instruction.
    - comment:  Optional human-readable comment.
    - label:    Optional assembly label.
    - action:   After search, action to perform on the instruction upon game execution.
    - glob:     TODO - During search, replace bytes at given indices with wildcards so that
                they match any bytes in memory.
    """

    assembly: str
    encoding: Optional[EncodingOptions] = None
    comment: Optional[str] = None
    label: Optional[str] = None
    action: Optional[InstrumentAction] = None
    glob: List[int] = field(default_factory=list)

    def as_assembly(self) -> str:
        """
        Return the instruction in text form that can be consumed by the GNU assembler.
        """

        encoding_string = "" if self.encoding is None else f"{{{self.encoding}}} "
        return f"    {encoding_string}{self.assembly}"

    def as_labels(self, line_number: Optional[int] = None) -> List[str]:
        """
        Return the labels that can be consumed by the GNU assembler.

        :param line_number: If a number `x` is provided, add a label "line_x".
        """
        lines = []

        if self.comment:
            lines.extend(["/*", self.comment, "*/"])
        if self.label:
            lines.append(f".set {self.label}, .")
        if line_number is not None:
            lines.append(f".set line_{line_number}, .")
        if self.action:
            lines.append(f".set {self.action.as_label}, .")

        return lines

    def as_labeled_assembly(self, line_number: Optional[int] = None) -> List[str]:
        """
        Return the instruction in text form with labels that can be consumed by the GNU assembler.

        :param line_number: If a number `x` is provided, add a label "line_x".
        """
        lines = self.as_labels(line_number)
        lines.append(self.as_assembly())

        return lines

    def __repr__(self) -> str:
        return f"Instruction(assembly={repr(self.assembly)}, encoding={repr(self.encoding)}, comment={repr(self.comment)}, label={repr(self.label)}, action={repr(self.action)}, glob={repr(self.glob)})"

    def __deepcopy__(self, memo):
        return Instruction(
            assembly=copy.deepcopy(self.assembly, memo),
            encoding=copy.deepcopy(self.encoding, memo),
            comment=copy.deepcopy(self.comment, memo),
            label=copy.deepcopy(self.label, memo),
            action=copy.deepcopy(self.action, memo),
            glob=copy.deepcopy(self.glob, memo),
        )


class Snippet:
    """
    A snippet of assembly code.
    """

    def _check_instructions(self):
        """
        Check label uniqueness.
        """
        labels: Dict[str, List[int]] = defaultdict(list)

        for idx, instruction in enumerate(self._instructions):
            if instruction.label:
                labels[instruction.label].append(idx)
            if instruction.action and instruction.action.as_label:
                labels[instruction.action.as_label].append(idx)

        duplicates = {label: indices for label, indices in labels.items() if len(indices) > 1}
        if duplicates:
            raise ValueError(f"Snippet '{self._name}' contains duplicate labels: {duplicates}")

        reserved_line_labels = [instruction.label for instruction in self._instructions if
                                instruction.label and instruction.label.startswith("line_")]
        if reserved_line_labels:
            raise ValueError(f"Snippet '{self._name}' contains reserved `line_` labels: {reserved_line_labels}")

    def __init__(self, name: str, machine: Machine, instructions: List[Instruction]):
        self._name = name
        self._machine = machine
        self._instructions = instructions
        self._label_offsets: Dict[str, int] = {}
        self._assembled_binary: List[bytes] = []

        _enforce_label(self._name)
        self._check_instructions()

    def __deepcopy__(self, memo):
        return Snippet(
            name=copy.deepcopy(self._name, memo),
            machine=copy.deepcopy(self._machine, memo),
            instructions=copy.deepcopy(self._instructions, memo),
        )

    @property
    def instructions(self) -> List[Instruction]:
        """
        List of instructions in the snippet.
        """
        return self._instructions

    @property
    def name(self) -> str:
        """
        Human-readable name of the snippet.
        """
        return self._name

    @property
    def machine(self) -> Machine:
        """
        Machine architecture for which the snippet is intended.
        """
        return self._machine

    @property
    def is_assembled(self) -> bool:
        """
        Returns True if the snippet has been assembled into a binary blob and all of its offsets generated.
        """
        return len(self._assembled_binary) > 0

    @property
    def assembled_size(self) -> int:
        """
        Returns the size of the assembled binary blob, or 0 if it has not been assembled.
        """
        return len(self._assembled_binary)

    @property
    def section_name(self) -> str:
        return f".{self.name}"

    @property
    def label_offsets(self) -> Dict[str, int]:
        """
        Returns a dictionary mapping label names to their offsets in the assembled binary blob.
        """
        return self._label_offsets

    @property
    def instrumented_instructions(self) -> Dict[int, InstrumentAction]:
        """
        Returns a dictionary mapping of byte offsets and corresponding instrumentation actions.
        """

        address_and_action: Dict[int, InstrumentAction] = {self._label_offsets[inst.action.as_label]: inst.action for
                                                           inst in self._instructions if inst.action is not None}

        return address_and_action

    def source_and_binary(self) -> List[Tuple[Instruction, bytes]]:
        """
        Returns a tuple of assembly source corresponding assembled binary.
        """
        return list(zip(self._instructions, self.assembled_line_by_line))

    def format_side_by_side(self) -> str:
        """
        Returns a formatted string representation of the assembly.
        """

        max_instruction_bytes = max(len(bin_instr) for bin_instr in self.assembled_line_by_line)

        def _format_hex(binary: bytes) -> str:
            return " ".join([f"{byte:02x}" for byte in binary]).ljust(max_instruction_bytes * 3)

        output = ""
        for source, binary in self.source_and_binary():
            for line in source.as_labels():
                output += "".ljust(max_instruction_bytes * 3 + 4) + f"{line}\n"
            output += f"  {_format_hex(binary)} {source.as_assembly()}\n"

        return output

    @property
    def assembly_source(self) -> str:
        """Assembly source as human-readable text"""

        # Generate content for asm source.
        lines = [f".section {self.section_name}, \"x\""]

        for idx, instruction in enumerate(self._instructions):
            lines.extend(instruction.as_labeled_assembly(idx))

        return "".join([line + "\n" for line in lines])

    @property
    def assembled_binary(self) -> bytes:
        return bytes(itertools.chain(self._assembled_binary))

    @property
    def assembled_line_by_line(self) -> List[bytes]:
        return self._assembled_binary or ([b""] * len(self._instructions))

    def assemble(self) -> bytes:
        """
        Assemble the snippet into a binary blob and generate offsets in the blob for each label.

        Invokes `objdump` on the generated binary blob to list offsets for each label.
        """
        if self.is_assembled:
            return bytes(itertools.chain(self._assembled_binary))

        system_arch = assembler_native_machine()
        if self._machine != system_arch:
            raise EnvironmentError(
                f"Snippet '{self._name}' for {self._machine} is not supported by {system_arch} `{get_gnu_assembler()}`.")

        with (NamedTemporaryFile("w+", suffix=".o", delete_on_close=False) as elf):
            elf.close()
            invoke_assembler(self.assembly_source, elf.name)

            label_offsets = invoke_objdump_dump_symbol(
                elf.name, self.section_name)
            raw_binary = invoke_objcopy_dump_section(
                elf.name, self.section_name)

            line_offsets = list()
            for idx in range(len(self._instructions)):
                offset = label_offsets.pop(f"line_{idx}")
                line_offsets.append(offset)
            line_offsets.append(len(raw_binary))

            # Cut raw binary into line-by-line
            line_by_line_binary = list()
            for idx in range(len(self._instructions)):
                bin_start = line_offsets[idx]
                bin_end = line_offsets[idx + 1]
                bin_assembly = raw_binary[bin_start:bin_end]
                line_by_line_binary.append(bin_assembly)

            assert len(line_by_line_binary) == len(self._instructions)

            self._label_offsets = label_offsets
            self._assembled_binary = line_by_line_binary

            return raw_binary


__all__ = [
    "EncodingOptions",
    "Machine",
    "InstrumentAction",
    "InstrumentBindVariable",
    "Instruction",
    "Snippet",
]
