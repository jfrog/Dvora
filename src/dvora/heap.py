from abc import ABC, abstractmethod
from typing import Dict, Union

from loguru import logger

from dvora.abi import ABI
from dvora.commons import PAGE_SIZE, PROT_READ, PROT_WRITE, align
from dvora.engine import UnicornEngine, VirtualMemory
from dvora.exceptions import HeapDoubleFreeError, HeapUnaccountedFreeError
from dvora.hooking import Hook, Literal, Pointer, bind_hook
from dvora.loader.elf.loader import ELFLoader


class HeapBase(ABC):
    """A base class for heap-like implementations."""

    #: The virtual memory object in which this heap lives. This serves as an
    #: interface for reading, writing and mapping memory
    vm: VirtualMemory
    #: The ABI of the emulated machine. Essentially used for packing/unpacking
    #: integers to/from memory.
    abi: ABI

    def __init__(self, vm: VirtualMemory, abi: ABI):
        self.vm = vm
        self.abi = abi

    def normalize(self, data: Union[str, bytearray, bytes, int]) -> bytes:
        """Take any *allocatable* python object, and convert it to a ``bytes``
        object:

        * Strings get encoded as "utf-8" and have a string terminator appended.
        * Integers are encoded as unsigned words.
        """
        if isinstance(data, bytearray):
            data = bytes(data)
        elif isinstance(data, str):
            data = bytes(data, encoding="utf8")
            data += b"\0"
        elif isinstance(data, int):
            data = self.abi.machine.pack_word(data)

        return data

    @abstractmethod
    def alloc(self, data: Union[str, bytearray, bytes, int]) -> int:
        """Allocate the requested data and copy it to the heap.

        Args:
            data: The data to allocate. Conversions will apply depending on the
                type of the data.

        Returns:
            The address of the allocated buffer.

        """

    def alloc_size(self, data: Union[str, bytearray, bytes, int], size: int) -> int:
        """Allocate memory with specified size and copy data to the heap.

        Args:
            data: The data to allocate.
            size: The size of the allocation.

        Returns:
            The address of the allocated buffer.
        """

    def malloc(self, size: int) -> int:
        """Allocate an empty buffer on the heap.

        Args:
            size: The size of the buffer to allocate.

        Returns:
            The address of the allocated buffer.

        """
        return self.alloc(bytes(size))


class Heap(HeapBase):
    """A growing heap (stack like) implementations.

    There's a single pointer that points to the top of the heap. Newly allocated
    data will move the pointer to point after the data.
    """

    #: Points to the next "free" memory
    heap_ptr: int
    heap_base: int

    def __init__(self, vm: VirtualMemory, abi: ABI):
        super().__init__(vm, abi)
        # Pre-allocate a heap
        self.heap_base = self.vm.allocate_padded(0x4000, PROT_READ | PROT_WRITE)
        self.reset()

    def reset(self):
        self.heap_ptr = self.heap_base

    def alloc(self, data: Union[str, bytearray, bytes, int]) -> int:
        data = self.normalize(data)
        logger.info(f"alloc({data[:10]!r}...)")
        # Align to 16 bytes and fill with zeroes (some implementations assume/
        # require that malloc returns a 16-byte aligned pointer for various
        # optimizations)
        data += bytes(16 - len(data) % 16)

        self.vm.set_mem(self.heap_ptr, data)
        to_ret = self.heap_ptr
        self.heap_ptr += len(data)
        logger.info(f"alloc({data[:10]!r}...) = {hex(to_ret)}")
        return to_ret

    def alloc_size(self, data: Union[str, bytearray, bytes, int], size: int) -> int:
        data = self.normalize(data)
        logger.info(f"alloc_size({data[:10]!r}...) with size {size}")
        # Align to 16 bytes and fill with zeroes (some implementations assume/
        # require that malloc returns a 16-byte aligned pointer for various
        # optimizations)
        data += bytes(16 - size % 16)

        self.vm.set_mem(self.heap_ptr, data)
        to_ret = self.heap_ptr
        self.heap_ptr += size
        logger.info(f"alloc_size({data[:10]!r}...) = {hex(to_ret)}")
        return to_ret


class SecureHeap(HeapBase):
    """This is not a heap per-se. Each allocation will attempts to find a free
    area in the virtual address space such that it's page-size aligned, and
    padded with two empty pages on each side of it.

    The actual allocated data will be positioned in such a way that it will end
    on a page boundary (and followed by an unallocated page).

    This is done so that heap overflows will trigger a page fault which can be
    caught and recorded.

    For example: Allocating a buffer ``0x1234`` bytes long, will try to find a
    free memory space of ``0x2000`` (``0x1234`` rounded up to page-size) plus an
    extra page on each side, resulting in an allocation of ``0x4000`` bytes.
    Suppose that the free space was found at ``0x50000``, then the data will
    reside at ``0x51dcc = 0x50000 + 0x3000 - 0x1234``.

    However, there's an assumption that allocated memory will be aligned to a
    16-byte boundary to allow various vector operations (these opcodes have
    these alignment requirements), so all in all, the returned pointer will be:
    ``align(0x51dcc, 16) = 0x51dc0``.

    This leaves a bit of wiggle space (12 bytes) for heap overflows in which
    they won't be detected, but...this is probably the best we can get using
    this method.
    """

    def alloc(self, data: Union[str, bytearray, bytes, int]) -> int:
        data = self.normalize(data)
        logger.info(f"alloc({data[:10]!r}...)")
        page_aligned_size = align(len(data), PAGE_SIZE)
        ptr = self.vm.find_vacant_memory(page_aligned_size + 2 * PAGE_SIZE)
        if ptr is None:
            return 0

        ptr += PAGE_SIZE
        self.vm.add_memory_page(ptr, PROT_READ | PROT_WRITE, bytes(page_aligned_size))

        ptr += page_aligned_size - len(data)
        ptr = align(ptr, 16)  # Required for vector load/store operations
        self.vm.set_mem(ptr, data)
        logger.info(f"alloc({data[:10]!r}...) = {hex(ptr)}")
        return ptr


class HeapAdapter:
    """A mediator between triggered hooks and a heap.
    This exists for several reasons:

    * Heaps implemented in the emulated code can be expensive and opaque to us
    * We want to be able to instrument discovery of various heap violations
    """

    #: A map from an address to whether the allocation is alive (``free``-ing
    #: turns the allocation off). We want to be able to track "dead" allocations
    #: to catch double-free errors.
    allocations: Dict[int, bool]
    #: A heap implementation
    heap: HeapBase

    def __init__(self, heap: HeapBase):
        self.heap = heap
        self.allocations = {}

    def bind(self, engine: UnicornEngine, abi: ABI, loader: ELFLoader):
        """Installs hooks on the various ``malloc`` library functions in the
        emulated process: ``malloc``, ``calloc``, ``free``

        Args:
            engine: The emulation engine in which the hooks are installed.
            abi: The architecture description that's used to extract the call
                parameters when the hooks is triggered.
            loader: The loading environment used to recover the addresses of the
                various ``malloc`` library functions.

        Todo:
            Hook ``realloc``
        """
        engine.hook(loader.dlsym("malloc"), bind_hook(abi, self.malloc))
        engine.hook(loader.dlsym("calloc"), bind_hook(abi, self.calloc))
        engine.hook(loader.dlsym("free"), bind_hook(abi, self.free))

    @Hook(Literal)
    def malloc(self, size: Literal) -> int:
        logger.info(f"malloc({size})")
        ret = self.heap.malloc(size.value)
        self.allocations[ret] = True
        return ret

    @Hook(Literal, Literal)
    def calloc(self, size: Literal, members: Literal) -> int:
        logger.info(f"calloc({size}, {members})")
        ret = self.heap.malloc(size.value * members.value)
        self.allocations[ret] = True
        return ret

    @Hook(Pointer)
    def free(self, pointer: Pointer) -> int:
        logger.info(f"free({pointer})")
        ptr = pointer.value
        if ptr not in self.allocations:
            raise HeapUnaccountedFreeError()
        if not self.allocations[ptr]:  # attempting to free a "freed" area
            raise HeapDoubleFreeError()

        self.allocations[ptr] = False
        return 0
