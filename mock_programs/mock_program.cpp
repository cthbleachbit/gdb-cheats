/* SPDX-License-Identifier: GPL-3.0 */
/*
 * Mock program to test cheat scripts with.
 * Decrement two counters (one on stack one on heap) every time enter is pressed.
 */

#include <thread>
#include <future>
#include "mock_program.h"

#include <iostream>

#include "thread_background.h"
#include "thread_update.h"


int main(int argc, char* argv[]) {
	using ValueT = uint32_t;

	size_t heap_offset = 1;
	size_t stack_offset = 1;
	size_t thread_count_bg = 16;
	ValueT heap_initializer = 65555;
	ValueT stack_initializer = 17;

	struct mock_global_sync global_state{};

	auto backgrounds = std::make_unique<std::future<void>[]>(thread_count_bg);
	for (size_t bg_thread_idx = 0; bg_thread_idx < thread_count_bg; ++bg_thread_idx) {
		backgrounds[bg_thread_idx] = std::async(std::launch::async, [&global_state] {
			task_background<ValueT>(global_state);
		});
	}
	std::future<void> foreground = std::async(std::launch::async, [&] {
		task_update<ValueT>(global_state, heap_initializer, heap_offset, stack_initializer, stack_offset);
	});

	/* Now that threads are up, listen to keypresses */
	while (true) {
		std::cerr << "READY... WAITING FOR KEYPRESS...";
		std::string input;
		std::getline(std::cin, input);
		if (!input.empty() && input.at(0) == 'q') {
			break;
		}
		std::cerr << " \n Iterating! \n";
		global_state.thread_cv.notify_all();
	}

	/* Shutdown */
	{
		std::lock_guard lock{global_state.thread_mutex};
		global_state.shutdown.store(true);
		global_state.thread_cv.notify_all();
	}

	/* Rejoin threads and exit */
	for (size_t bg_thread_idx = 0; bg_thread_idx < thread_count_bg; ++bg_thread_idx) {
		backgrounds[bg_thread_idx].wait();
	}
	foreground.wait();

	return 0;
}
