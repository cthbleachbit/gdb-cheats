# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Build and Run

```bash
# Install package in development mode
pip install -e .[test,dev]

# Run tests
pytest

# Launch GDB with cheats plugin
cheats-gdb [gdb-args]
```

## Architecture

**gdb_cheats** is a GDB plugin for memory search and value locking (cheat engine functionality).

### Core Components

- **`core.py`** - Core types: `ValueType` (enum for int/float types), `VariableDefinition` (memory address bookmark), `SearchSession` (stateful search), `CheatSession` (global state), `LockedValueWatchpoint` (hardware write watchpoint)

- **`search.py`** - Memory search implementations:
  - `GdbBuiltInSearch` - Uses `gdb.Inferior.search_memory()` for fast exact byte matching
  - `MultiProcessingSearchImpl` - Parallel search using Python multiprocessing allowing custom value predicates

- **`command.py`** - GDB commands under `cheat` prefix:
  - `cheat session` - Create/summarize/delete sessions
  - `cheat search` - Create populate, narrow, and summarize searches
  - `cheat variable` - Manage variable bookmarks
  - `cheat lock` - Create/enable/disable/delete watchpoints

- **`utilities.py`** - Type aliases and non-gdb interfacing utilities. Must not import GDB module here.

### Execution Model

1. `cheats-gdb` wrapper script launches GDB with the cheat module directory added to GDB's python search path, and sources `cheats.py`.
2. `cheats.py` registers all GDB commands via `register_gdb_commands()` and initializes an active session state.
3. Search flows: `cheat search create <type>` → `cheat search populate <value>` → optional `cheat search narrow <value>` → `cheat search define_variable <name>`
4. Locking: `cheat lock create <var-index> <value>` creates a hardware write watchpoint.

### Inferior process memory handling

- Uses `/proc/pid/maps` to discover writable+readable segments for search
- Resolves `MADV_GUARD_REMOVE` constant for glibc 2.42+ stack guard page handling
