# SPDX-License-Identifier: GPL-3.0

"""
GDB Cheats - Modular memory search interface
"""

import abc
import functools
import importlib
import itertools
import logging
import multiprocessing
import multiprocessing.pool
import pprint
from typing import Tuple, List

# gdb is an embedded module - not available under MP forkserver / spawn.
# import gdb
import tqdm

from gdb_cheats.utilities import Address, Offset, Buffer, ValuePredicate, AddressPredicate

_logger = logging.getLogger("search")


class MemorySearchImpl(abc.ABC):
    """
    Memory search interface.
    The class defines required APIs that expose process memory ranges.
    """

    def __init__(self, inferior):
        self._gdb = importlib.import_module("gdb")
        self._logger = _logger.getChild(self.__class__.__name__)
        self._inferior = inferior

    @staticmethod
    def address_filter_true(address: Address) -> bool:
        """
        Dummy address filter that accepts all addresses.
        Conforms to AddressPredicate signature.
        """
        return True

    @staticmethod
    def address_filter_alignment_offset(address: Address, /, alignment: Offset, offset: Offset) -> bool:
        """
        Address filter that accepts addresses based on alignment and offset.
        Conforms to AddressPredicate signature.
        :param address: Address to filter - supplied during search.
        :param alignment: Desired alignment - prepopulate with functools.partial.
        :param offset:    Desired offset - prepopulate with functools.partial.
        """
        return address % alignment == offset

    @staticmethod
    def value_filter_exact(target: Buffer, compare: Buffer) -> bool:
        """
        Value filter that accepts values exactly matching a target value.
        Conforms to ValuePredicate signature.
        """
        return bytes(target) == bytes(compare)

    @abc.abstractmethod
    def filter(
            self, search_areas: List[Tuple[Address, Address]],
            granularity: int,
            value_filter: ValuePredicate,
            address_filter: AddressPredicate = address_filter_true,
    ) -> List[Address]:
        """
        Search memory for given search areas.
        :param search_areas:    A list of (start, end) each describing a search area.
        :param granularity:     The granularity of the search (in bytes).
        :param value_filter:    A predicate checking whether the value matches user criteria.
        :param address_filter:  A predicate checking whether an address matches user criteria.
                                Optional - omit to accept all addresses.
        :return: A list of addresses in the search areas that satisfy the search criteria.
        """
        ...

    def exact(
            self,
            search_areas: List[Tuple[Address, Address]],
            value: Buffer,
            address_filter: AddressPredicate = address_filter_true,
    ) -> List[Address]:
        """
        Search memory for given search areas.
        :param search_areas:    A list of (start, end) each describing a search area.
        :param address_filter:  A predicate checking whether an address matches user criteria.
        :param value:    Exact sequence of bytes to match,
        :return: A list of addresses in the search areas that satisfy the search criteria.
        """
        value_filter = functools.partial(MemorySearchImpl.value_filter_exact, value)
        return self.filter(search_areas, len(value), value_filter, address_filter)

    def narrow_filter(
            self,
            pointers: List[Address],
            granularity: int,
            value_filter: ValuePredicate,
    ) -> List[Address]:
        """
        Narrow down a list of pointers with a condition on its current value.
        :param pointers:        A list of pointers.
        :param granularity:     The granularity of the search (in bytes).
        :param value_filter:    A predicate checking whether the value matches user criteria.
        :return: Remaining pointers that matches the user criteria.
        """
        remaining_candidates: List[Address] = []

        for candidate in tqdm.tqdm(pointers, desc="Narrowing down", unit="items"):
            try:
                current_pattern = bytes(self._inferior.read_memory(
                    candidate, granularity))
            except self._gdb.MemoryError:
                # This memory might have been remapped. Consider this candidate eliminated
                self._logger.debug(f"Eliminating candidate 0x{candidate:016x}")
                continue

            if value_filter(current_pattern):
                self._logger.debug(f"Keeping candidate 0x{candidate:016x}")
                remaining_candidates.append(candidate)
            else:
                self._logger.debug(f"Eliminating candidate 0x{candidate:016x}")

        return remaining_candidates

    def narrow_exact(self, pointers: List[Address], value: Buffer) -> List[Address]:
        """
        Narrow down a list of pointers keeping those with the specified value.
        :param pointers:        A list of pointers.
        :param value:           The allowed value.
        :return:  Remaining pointers that matches the value.
        """
        value_filter = functools.partial(MemorySearchImpl.value_filter_exact, value)
        return self.narrow_filter(pointers, len(value), value_filter)


class GdbBuiltInSearch(MemorySearchImpl):
    """
    GDB internal search implementation. This only allows exact memory match.
    """

    def __init__(self, inferior):
        super().__init__(inferior)

    def filter(
            self,
            search_areas: List[Tuple[Address, Address]],
            granularity: int,
            value_filter: ValuePredicate,
            address_filter: AddressPredicate = MemorySearchImpl.address_filter_true,
    ) -> List[Address]:
        raise NotImplementedError("GDB internal search only allows exact memory match.")

    def _gdb_search_area(
            self,
            start: Address, end: Address,
            value: Buffer,
            address_filter: AddressPredicate,
    ) -> List[Address]:
        """
        Search a single memory area with gdb
        :param start:  start address to search
        :param end:    end address to search
        :param value:   value to search
        :param address_filter:  A predicate checking whether an address matches user criteria.
        :return:       list of matching addresses
        """
        search_start = start
        search_end = end

        pointer_candidates: List[Address] = []
        while True:
            search_length = search_end - search_start
            if search_length <= 0:
                break

            # GDB only returns at most 1 result every time search_memory() is invoked.
            # To search through the space further calls are required starting from last matching address.
            try:
                search_result = self._inferior.search_memory(
                    search_start, search_length, value)
            except self._gdb.MemoryError as e:
                self._logger.error(f"Skipping unreadable segment {start:016x}-{end:016x}!",
                                   exc_info=e)
                continue
            except ValueError as e:
                self._logger.error(
                    f"Skipping segment {start:016x}-{end:016x}!", exc_info=e)
                continue

            if search_result is None:
                # No matches found till end of the search range
                break

            # GDB search_memory() returns gibberish if the memory search fails to read the memory.
            # At least check if the search result is a valid address inside the search range.
            if search_result < search_start or search_result >= search_end:
                self._logger.error(f'Area address 0x{search_result:016x}+{search_length:016x} is not accessible!')
                break

            self._logger.debug(
                f"Found match at 0x{search_result:016x}")
            if address_filter(search_result):
                pointer_candidates.append(Address(search_result))
            else:
                self._logger.debug(f"Excluding address 0x{search_result:016x} due to filtering.")
            search_start = search_result + len(value)

        return pointer_candidates

    def exact(
            self,
            search_areas: List[Tuple[Address, Address]],
            value: Buffer,
            address_filter: AddressPredicate = MemorySearchImpl.address_filter_true,
    ) -> List[Address]:
        total_length = sum([end - start for start, end in search_areas])
        pointer_candidates: List[Address] = []

        with tqdm.tqdm(
                total=total_length,
                desc="Searching",
                unit="bytes",
                unit_scale=True,
                unit_divisor=1024,
        ) as progress:
            for start, end in search_areas:
                progress.update(end - start)
                pointer_candidates.extend(self._gdb_search_area(start, end, value, address_filter))

        return pointer_candidates


def _mp_worker_search_range(
        start: Address, end: Address,
        memory: Buffer,
        granularity: int,
        value_filter: ValuePredicate,
        address_filter: AddressPredicate,
) -> List[Address]:
    """
    Searches a specified range of memory for addresses matching filtering criteria.

    Returns:
        List[Address]: A list of memory addresses that satisfy the filtering criteria.
    """
    area_size = end - start
    value_start_offsets = range(0, area_size, granularity)
    candidates: List[Address] = []

    for value_start_offset in value_start_offsets:
        value_address = start + value_start_offset
        if not address_filter(value_address):
            continue

        value_end_offset = min(value_start_offset + granularity, area_size)
        value_buffer = memory[value_start_offset:value_end_offset]
        if not value_filter(bytes(value_buffer)):
            continue

        candidates.append(value_address)

    return candidates


class MultiProcessingSearchImpl(MemorySearchImpl):
    """
    Python parallel search implementation
    """

    def __init__(self, inferior):
        super().__init__(inferior)
        self._split_size = 16 * 1024 * 1024  # 16 MiB
        # Forcing fork so that built-in types carry over.
        # Access to the inferior is, however, not possible here.
        # No GDB APIs may be used inside the multiprocessing pool.
        self._mp = multiprocessing.get_context("fork")

    def _search_range_mp(
            self,
            start: Address, end: Address,
            granularity: int,
            value_filter: ValuePredicate,
            address_filter: AddressPredicate,
            mp_pool: multiprocessing.pool.Pool,
    ) -> List[Address]:
        # Always perform granularity-aligned splits
        effective_split = self._split_size // granularity * granularity

        if end - start < effective_split:
            memory = self._inferior.read_memory(start, end - start)
            return _mp_worker_search_range(start, end, bytes(memory), granularity, value_filter, address_filter)

        # Chop up into smaller ranges
        chunk_start_offsets = list(range(start, end, effective_split))
        chunk_end_offsets = [min(s + effective_split, end) for s in chunk_start_offsets]
        search_ranges = list(zip(chunk_start_offsets, chunk_end_offsets))
        chunks = [bytes(self._inferior.read_memory(s, e - s)) for s, e in search_ranges]
        mapped_function_params = list(zip(chunk_start_offsets, chunk_end_offsets, chunks))

        mapped_function = functools.partial(
            _mp_worker_search_range,
            granularity=granularity,
            value_filter=value_filter,
            address_filter=address_filter,
        )
        try:
            nested_candidates = mp_pool.starmap(mapped_function, mapped_function_params)
            return list(itertools.chain.from_iterable(nested_candidates))
        except Exception as e:
            _logger.error("Search failed", exc_info=e)
            pprint.pprint(search_ranges)
            return []

    def filter(
            self,
            search_areas: List[Tuple[Address, Address]],
            granularity: int,
            value_filter: ValuePredicate,
            address_filter: AddressPredicate = MemorySearchImpl.address_filter_true,
    ) -> List[Address]:
        total_length = sum([end - start for start, end in search_areas])
        pointer_candidates: List[Address] = []

        with tqdm.tqdm(
                total=total_length,
                desc="Searching",
                unit="bytes",
                unit_scale=True,
                unit_divisor=1024,
        ) as progress:
            with self._mp.Pool() as pool:
                for start, end in search_areas:
                    progress.update(end - start)
                    pointer_candidates.extend(
                        self._search_range_mp(start, end, granularity, value_filter, address_filter, pool))

        return pointer_candidates
