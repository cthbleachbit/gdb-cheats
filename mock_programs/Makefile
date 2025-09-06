#/usr/bin/env make -f
# SPDX-License-Identifier: GPL-3.0

all: bin_mock_program bin_mock_program_debug

bin_mock_program: mock_program.cpp thread_background.h thread_update.h mock_program.h
	g++ -O2 -s -Wall --std=gnu++23 $^ -o $@

bin_mock_program_debug: mock_program.cpp thread_background.h thread_update.h mock_program.h
	g++ -O0 -ggdb -Wall --std=gnu++23 $^ -o $@

clean:
	rm -f bin_mock_program bin_mock_program_debug

.PHONY: all clean
