/* SPDX-License-Identifier: GPL-3.0 */

#ifndef GDB_CHEATS_MOCK_PROGRAM_H
#define GDB_CHEATS_MOCK_PROGRAM_H

#include <atomic>
#include <mutex>
#include <condition_variable>

#include <iostream>
#include <type_traits>
#include <limits>
#include <random>

constexpr size_t HEAP_COUNT = 1024 * 1024;
constexpr size_t STACK_COUNT = 1024;

struct mock_global_sync {
	std::mutex thread_mutex{};
	std::condition_variable thread_cv{};
	std::atomic<bool> shutdown{false};
};

extern std::unique_ptr<mock_global_sync> mock_global_sync;

#endif //GDB_CHEATS_MOCK_PROGRAM_H
