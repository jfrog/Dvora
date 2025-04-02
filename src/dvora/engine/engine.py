from abc import ABC, abstractmethod
from operator import attrgetter
from typing import Dict, List, Optional

import attr

from dvora.commons import (
    PAGE_SIZE,
    PROT_READ,
    PROT_WRITE,
    STACK_SIZE,
    align_up,
)
from dvora.exceptions import NotEnoughMemory
from dvora.machine import Machine


@attr.s(auto_attribs=True)
class MemoryChunk:
    access: int
    size: int
    data: bytes


@attr.s(auto_attribs=True)
class MemoryMap:
    addr: int
    size: int
    name: str
    access: int

    @property
    def end(self) -> int:
        return self.addr + self.size


class CPU(ABC):
    @abstractmethod
    def init_regs(self):
        pass

    @abstractmethod
    def get_gpreg(self) -> Dict[str, int]:
        pass

    # These (__getattr__, __setattr__) are here to help mypy figure out typing
    # for getattr/setattr on the CPU "abstract" class
    def __setattr__(self, name: str, value: int):
        # pylint: disable=useless-super-delegation
        super().__setattr__(name, value)

    def __getattr__(self, name: str) -> int:
        return 0

    def set_thread_pointer(self, thread_pointer: int) -> None:
        pass


class VirtualMemory(ABC):
    mappings: List[MemoryMap]

    def __init__(self):
        self.mappings = []

    # pylint: disable=too-many-arguments
    def mmap(self, addr: int, size: int, prot: int, fp, offset: int, alignment: int):
        size_aligned = align_up(size, alignment)

        cur = fp.seek(offset)
        data = fp.read(size_aligned)
        fp.seek(cur)

        padding = bytes(size_aligned - len(data))

        self.add_memory_page(addr, prot, data + padding, name="")

    @abstractmethod
    def get_all_memory(self) -> Dict[int, MemoryChunk]:
        pass

    @abstractmethod
    def get_mem(self, addr: int, size: int) -> bytes:
        pass

    @abstractmethod
    def set_mem(self, addr: int, content: bytes):
        pass

    @abstractmethod
    def add_memory_page(self, addr: int, access: int, item_str: bytes, name: str = ""):
        pass

    def is_vacant(self, start: int, size: int) -> bool:
        """Check whether the specified memory range is not occupied by any
        existing mapping.

        Args:
            start: The start of the memory range
            size: The size of the memory range

        Returns:
            ``True`` if there is any existing map that overlaps the specified
            range. ``False`` otherwise.

        """
        end = start + size
        for mapping in sorted(self.mappings, key=attrgetter("addr")):
            if start <= mapping.addr <= end:
                return False
            if start <= mapping.end <= end:
                return False

        return True

    def find_vacant_memory(
        self, size: int, starting_at: int = PAGE_SIZE
    ) -> Optional[int]:
        """Finds the first unoccupied memory range of the specified size.
        Optionally specify where to start the search.

        Args:
            size: The size of the memory to look for.
            starting_at (optional): Where to start the scan. Defaults to
                ``PAGE_SIZE`` so that memory won't ever be allocated at 0
                (``NULL``).

        Returns:
            The start address of the free memory. If none is found, returns None.

        """
        ends = [max(starting_at, PAGE_SIZE)]
        starts = []
        for mapping in sorted(self.mappings, key=attrgetter("addr")):
            if mapping.end < starting_at:
                continue
            starts.append(mapping.addr)
            ends.append(mapping.addr + mapping.size)
        starts.append(0x100000000)

        for hole_start, hole_end in zip(ends, starts):
            hole_size = hole_end - hole_start
            if size <= hole_size:
                return hole_start

        return None

    def allocate_padded(
        self, size: int, protection: int = PROT_READ | PROT_WRITE
    ) -> int:
        """Allocate a chunk of memory with the specified size with
        ``PAGE_SIZE``-d padding around it.

        Args:
            size: The size of the memory to allocate. It will be aligned to the
                next ``PAGE_SIZE`` boundary.
            protection: Memory protection properties

        Returns:
            The start address of the allocated memory.

        Raises:
            NotEnoughMemory: No vacant memory with the requested properties
                could be found.

        """
        size = align_up(size, PAGE_SIZE)
        load_address = self.find_vacant_memory(size + PAGE_SIZE * 2)
        if not load_address:
            # Either ``find_vacant_memory`` returned ``None``, or 0 (which is
            # also unacceptable as 0 is ``NULL`` and is used to indicate
            # invalid memory).
            raise NotEnoughMemory(hex(size))
        # Found a large enough hole, pad it with an empty page to the
        # left
        load_address += PAGE_SIZE
        self.add_memory_page(load_address, protection, bytes(size))
        return load_address


class Engine(ABC):
    """An abstract class representing an emulated target. The main function of
    an ``Engine`` is to be able to control basic execution: ``run``.

    As such, it unifies a ``CPU`` for register access, ``VirtualMemory`` for
    memory access and a ``Machine`` to interpret scalar values between the
    emulated CPU and the host to emulated memory.

    In addition, this class provides abstraction for accessing various key
    elements of a running context such as the program-counter and stack-pointer,
    as well as basic state management (take & restore snapshot).
    """

    #: A snapshot of the emulated memory. This is a map from address to a
    #: ``MemoryChunk`` object.
    vm_mem: Dict[int, MemoryChunk]
    #: A snapshot of the emulated CPU. This is a map from register name to a
    #: value.
    vm_regs: Dict[str, int]

    #: Interface to the emulated memory.
    vm: VirtualMemory
    #: Interface to the emulated CPU.
    cpu: CPU
    #: Interface to the machines properties (word size, endianness, ...)
    machine: Machine

    def __init__(self, machine: Machine):
        self.machine = machine

    def take_snapshot(self):
        self.vm_mem = self.vm.get_all_memory()
        self.vm_regs = self.cpu.get_gpreg()

    def restore_snapshot(self, memory=True):
        # Restore VM
        if memory:
            self.vm.restore_mem_state(self.vm_mem)

        # Restore registers
        self.cpu.set_gpreg(self.vm_regs)

    def init_stack(self):
        """Allocate a stack at a fixed location (``STACK_BOTTOM``) and set up
        the CPU's stack-pointer to point to the top of it.

        Todo:
            * Add a ``stack_size`` parameter
            * Allocate the stack where-ever there's free space
        """
        stack_bottom = self.vm.allocate_padded(STACK_SIZE)
        stack_top = stack_bottom + STACK_SIZE
        self.sp = stack_top

    @property
    def sp(self):
        return getattr(self.cpu, self.machine.sp_name)

    @sp.setter
    def sp(self, sp):
        setattr(self.cpu, self.machine.sp_name, sp)

    @property
    def pc(self):
        return getattr(self.cpu, self.machine.pc_name)

    def push_word(self, value: int):
        self.sp -= self.machine.sizeof_word
        self.vm.set_mem(self.sp, self.machine.pack_word(value))

    def peek_stack(self, offset: int, size: int) -> bytes:
        return self.vm.get_mem(self.sp + offset, size)

    @abstractmethod
    def run(self, address: int, timeout_seconds: int, n_steps: int = 0) -> bool:
        pass
