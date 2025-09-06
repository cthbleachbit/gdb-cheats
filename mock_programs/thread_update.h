#pragma once

#include "mock_program.h"

/**
 * Background update thread. Decrement heap and stack on demand.
 */
template <typename ValueT>
int task_update(struct mock_global_sync& global_state, const ValueT initial_heap, const size_t update_heap_offset,
                const ValueT initial_stack, const size_t update_stack_offset) {
	static_assert(std::is_integral_v<ValueT> && std::is_unsigned_v<ValueT>);

	std::cerr << "Update thread starting." << &global_state << std::endl;

	/* Allocate heap and stack space */
	constexpr ValueT heap_count = HEAP_COUNT / sizeof(ValueT);
	constexpr ValueT stack_count = STACK_COUNT / sizeof(ValueT);
	if (update_heap_offset >= heap_count || update_stack_offset >= stack_count) {
		abort();
	}
	auto heap = std::make_unique<ValueT[]>(heap_count);
	ValueT stack[stack_count];

	/* Fill stack and heap */
	std::fill(heap.get(), heap.get() + stack_count, initial_heap);
	std::fill(stack, stack + stack_count, initial_stack);

	while (true) {
		/* Wait for signal or shutdown */
		{
			std::unique_lock lock(global_state.thread_mutex);
			global_state.thread_cv.wait(lock);
			if (global_state.shutdown.load() == true) {
				return 0;
			}
		}

		/* Decrement on demand */
		heap[update_heap_offset] = heap[update_heap_offset] - 1;
		stack[update_stack_offset] = stack[update_stack_offset] - 1;
	}
}
