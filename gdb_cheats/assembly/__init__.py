"""
This module contains utilities to look for assembly instructions in GDB.

Usage:
- Define snippets containing assembly instructions.
- `Snippet.assemble` to assemble the snippet into machine code.
- `CodeSearch.search_code` to search for the snippet in memory.
- `CodeSearch.enable_instrumentation` to queue instrumentation breakpoints for the snippet.
"""
