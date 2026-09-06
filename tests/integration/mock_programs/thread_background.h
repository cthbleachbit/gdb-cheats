/* SPDX-License-Identifier: GPL-3.0 */

#pragma once

#include "mock_program.h"

/**
 * Persistent background thread. Fill memory space with random data at every update.
 */
template <typename ValueT>
int task_background(struct mock_global_sync& global_state) {
	static_assert(std::is_integral_v<ValueT> && std::is_unsigned_v<ValueT>);

	std::cerr << "Background thread starting." << &global_state << std::endl;


	/* Allocate heap and stack space */
	constexpr ValueT heap_count = HEAP_COUNT / sizeof(ValueT);
	constexpr ValueT stack_count = STACK_COUNT / sizeof(ValueT);
	auto heap = std::make_unique<ValueT[]>(heap_count);
	ValueT stack[stack_count];

	/* Create RNG */
	std::random_device random_device;
	std::mt19937 generator(random_device());
	std::uniform_int_distribution<ValueT> distribution(0, std::numeric_limits<ValueT>::max());

	while (true) {
		/* Fill data */
		for (ValueT i = 0; i < heap_count; i++) {
			heap[i] = distribution(generator);
		}
		for (ValueT& i : stack) {
			i = distribution(generator);
		}

		/* Wait for signal or shutdown */
		{
			std::unique_lock lock(global_state.thread_mutex);
			global_state.thread_cv.wait(lock);
			if (global_state.shutdown.load() == true) {
				return 0;
			}
		}
	}
}
