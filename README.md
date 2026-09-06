# GDB cheats plugin

Cheat engine in the form of a gdb plugin.

Written out of tilted spite, thanks to sheer difficulty progression of Hollow Knight: Silksong.

## Requirements

- Works on Linux. Untended and may or may not work on macOS. Definitely does not work on Windows.
- GDB with python3.14+ support.
- GCC / binutils objdump + objcopy. Ensure `gcc`, `as`, `objdump` and `objcopy` are in your `PATH`. Alternatively, set
  `GCC`, `AS`, `OBJDUMP` and `OBJCOPY` environment variables to point to the executables.
- Python package `tqdm` for drawing progress bars.

To load the plugin, install the python package and run `cheats-gdb`. This is a gdb wrapper that loads the plugin.

## Memory search implementations

### `gdb` - GDB built-in memory search

Uses gdb built-in `gdb.Inferior.search_memory()` to look for a byte sequence.

* __Pros__: Fast as search happens in native gdb code.
* __Cons__: Only finds exact byte-by-byte match.

### `mp` - Python multiprocessing memory search

Reads segments into python memory and parallelize search across multiple subprocesses.

* __Pros__: More flexible. Search procedure accepts arbitrary `Callable[[bytes], bool]` predicate. This lets you search
  ranges or apply custom decision flow against potential matches. __ONLY available via python APIs.__
* __Cons__: Slower and more memory consumption.

## Gdb commands

All commands live under `cheat` prefix and support in-debugger `help <command>`.

### `cheat session` - Manage global information

* `switch <name>` - Switch to the given session. When `name` is omitted, switch to the default session.
* `summarize` - Print a summary of all currently tracked information.
* `delete` - Delete the current session. All variables, watchpoints, and in-progress search will be deleted.

### `cheat search` - Search for patterns in the memory space

#### `create <data type>` - Create a new search context

Currently supported data types are signed and unsigned integers of 1, 2, 4, or 8 bytes plus single/double-precision
floating points. You may refer to the types like `u8` and `i64`. Floating points are represented by `f32` and `f64`.
Data type specified here will apply to all future search operations. To switch data type and start over, use this
command again with the desired type.

This will replace an existing search if there is one.

#### `populate [-s gdb|mp] [-a ALIGN] [-o OFFSET] <value>` - Populate initial candidates

Exhaustively look for byte sequences that represent `<value>` of user-specified type in the program memory space.

Use `-a ALIGN` and `-o OFFSET` to look for certain structured data. Example: `-a 4096 -o 0x21c` will only match pointers
at offset `0x21c` past 4096B aligned pages.

#### `summary [-l print_limit]` - Summarize current search status

Prints current search types and candidate pointers. By default, the command only prints potential matches when there are
no more than 100 candidates. Pass `-l N` to change the limit or `-l 0` to print everything.

#### `define_variable <name> [index]` - Create variable definition from search results

Create a variable bookmark at one of the search results. You can then create value locks on the variable. When there's
more than one candidate, you'll want to pass `index` to select one of the addresses for the variable.

### `cheat variable` - Manage variable bookmarks

* `create <name> <type> <address>` - Manually bookmark an address
* `summary` - Prints a numbered list of currently bookmarked variables and in-memory values
* `set <index> <value>` - Set the value pointed by the bookmark.
* `delete <index>` - Remove a bookmarked variable.

### `cheat lock` - Freeze variables values

A lock is a gdb watchpoint that denies the game from updating a certain memory location. The watchpoint should be
hardware-assisted on most platforms, though the number of hardware-assisted watchpoints supported by your CPU may vary.

* `create <variable index> <value>` - Create a lock on a variable freezing it at the specified value. If there's already
  a lock on the variable, the existing lock is updated to match the value specified here.
* `enable <variable index>` - Enable a lock
* `disable <variable index>` - Temporarily disables a lock
* `delete <variable index>` - Destroy a lock.

Note that lock watchpoints created by the cheat engine are separate and not shown under GDB `info watchpoints`.

## Python API

Internally, the python API offers more degrees of freedom than the GDB command line. For more complex value filtering,
create your own Python script, instantiate a new search session, and operate on it directly:

```python
import functools

from gdb_cheats.session_management import get_or_create_session
from gdb_cheats.core import SearchSession, ValueType, VariableDefinition
from gdb_cheats.search import MemorySearchImpl
from gdb_cheats.utilities import Buffer

session = get_or_create_session("my_cheats")


# Searching for a 32b floating point value smaller than 114514.125
# This value lives at 0x55c from 4K aligned boundary
def value_criteria(sample: Buffer) -> bool:
    if len(sample) < ValueType.F32.length_bytes:
        return False
    return ValueType.F32.from_buffer(sample) < 114514.125


address_criteria = functools.partial(
    MemorySearchImpl.address_filter_alignment_offset,
    alignment=4096,
    offset=0x55c
)

my_search = SearchSession(ValueType.F32)
# Need to use `mp` implementation for arbitrary value filter predicate
my_search.populate_filter(value_criteria, "mp", address_criteria)
my_search.summarize(print_limit=0)

# Define a variable from the first search result
variable = VariableDefinition("name", ValueType.F32, my_search.candidates[0])
session.variables.append(variable)

# Create a lock on the variable
session.variable_lock_create(variable, 1919810.5)
```

You can load any Python script either by sourcing it at gdb prompt or importing it like a module in gdb python prompt. 
