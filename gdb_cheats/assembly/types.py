import abc
import enum
import string
from collections import defaultdict
from dataclasses import dataclass, field
from tempfile import NamedTemporaryFile
from typing import Optional, List, Dict

from gdb_cheats.assembly.assembler import invoke_assembler, invoke_objdump_dump_symbol, invoke_objcopy_dump_section


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

    def __repr__(self) -> str:
        raise NotImplementedError()

    def __str__(self) -> str:
        return repr(self)


@dataclass
class InstrumentBindVariable(InstrumentAction):
    """
    Indicate that the cheat engine should bind a variable to the value of a GDB expression.

    The variable name must be a valid assembly label.
    The expression is evaluated BEFORE the instruction is executed.
    """
    expression: str
    variable_name: str

    def __post_init__(self):
        # require variable name to be a valid assembly label
        _enforce_label(self.variable_name)

    @property
    def as_label(self) -> str:
        return f"bind_variable_{self.variable_name}"

    def __repr__(self) -> str:
        return f"InstrumentBindVariable(expression={repr(self.expression)}, variable_name={repr(self.variable_name)})"

    def __str__(self) -> str:
        return repr(self)


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

    def as_gnu_assembly(self) -> List[str]:
        """
        Return the instruction as lines that can be consumed by the GNU assembler.
        """
        lines = []
        if self.comment:
            lines.extend(["/*", self.comment, "*/"])
        if self.label:
            lines.append(f".set {self.label}, .")
        if self.action:
            lines.append(f".set {self.action.as_label}, .")

        encoding_string = "" if self.encoding is None else f"{{{self.encoding}}} "
        lines.append(f"    {encoding_string}{self.assembly}")

        return lines

    def __repr__(self) -> str:
        return f"Instruction(assembly={repr(self.assembly)}, encoding={repr(self.encoding)}, comment={repr(self.comment)}, label={repr(self.label)}, action={repr(self.action)}, glob={repr(self.glob)})"


@dataclass
class Snippet:
    """
    A snippet of assembly code.
    """
    # Name of the snippet - used as elf section name.
    _name: str
    # List of instructions in the snippet.
    _instructions: List[Instruction]
    # Offsets of user-defined and instrumentation labels in the snippet.
    _label_offsets: Dict[str, int] = field(default_factory=dict)
    # Assembled blob
    _assembled_binary: Optional[bytes] = None

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

    def __init__(self, name: str, instructions: List[Instruction]):
        self._name = name
        self._instructions = instructions
        self._offsets = []

        _enforce_label(self._name)
        self._check_instructions()

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
    def is_assembled(self) -> bool:
        """
        Returns True if the snippet has been assembled into a binary blob and all of its offsets generated.
        """
        return self._assembled_binary is not None

    @property
    def assembled_size(self) -> int:
        """
        Returns the size of the assembled binary blob, or 0 if it has not been assembled.
        """
        return len(self._assembled_binary) if self._assembled_binary is not None else 0

    @property
    def section_name(self) -> str:
        return f".{self.name}"

    @property
    def assembly_source(self) -> str:
        """Assembly source as human-readable text"""

        # Generate content for asm source.
        lines = [f".section {self.section_name}, \"x\""]

        for instruction in self._instructions:
            lines.extend(instruction.as_gnu_assembly())

        return "".join([line + "\n" for line in lines])

    def assemble(self) -> bytes:
        """
        Assemble the snippet into a binary blob and generate offsets in the blob for each label.

        Invokes `objdump` on the generated binary blob to list offsets for each label.
        """
        if self._assembled_binary is not None:
            return self._assembled_binary

        with (NamedTemporaryFile("w+", suffix=".o", delete_on_close=False) as elf):
            elf.close()
            invoke_assembler(self.assembly_source, elf.name)

            label_offsets = invoke_objdump_dump_symbol(elf.name, self.section_name)
            raw_binary = invoke_objcopy_dump_section(elf.name, self.section_name)

            self._label_offsets = label_offsets
            self._assembled_binary = raw_binary

            return raw_binary


__all__ = [
    "EncodingOptions",
    "InstrumentAction",
    "InstrumentBindVariable",
    "Instruction",
    "Snippet",
]
