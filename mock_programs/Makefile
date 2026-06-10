#/usr/bin/env make -f
# SPDX-License-Identifier: GPL-3.0

.PHONY: all
all: interactive

# =================================================
# Compile targets
# =================================================

bin_mock_program: mock_program.cpp thread_background.h thread_update.h mock_program.h
	g++ -O2 -s -Wall --std=gnu++23 $^ -o $@

bin_mock_program_debug: mock_program.cpp thread_background.h thread_update.h mock_program.h
	g++ -O0 -ggdb -Wall --std=gnu++23 $^ -o $@

# =================================================
# Test targets
# =================================================

GDB_CHEATS_ARGS = -ex "source ../cheats.py"
GDB_TESTS_ARGS = -ex "source ./tests/test_base.py" -ex "source ./tests/test_entry.py"

# Interactive gdb
.PHONY: interactive
interactive: bin_mock_program_debug
	gdb ./bin_mock_program_debug \
		$(GDB_CHEATS_ARGS)

.PHONY: test
test: bin_mock_program_debug
	gdb ./bin_mock_program_debug \
		$(GDB_CHEATS_ARGS) \
		$(GDB_TESTS_ARGS) \
 		-ex "source -s test_search_i32.py"

.PHONY: clean
clean:
	rm -f bin_mock_program bin_mock_program_debug
