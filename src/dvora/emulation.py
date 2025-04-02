from typing import Iterable, List, Optional, cast

import capstone
from loguru import logger

from dvora.abi import ABI, get_abi_class
from dvora.commons import PROT_READ, PROT_WRITE, Chunk
from dvora.engine import UnicornEngine
from dvora.heap import Heap, HeapAdapter
from dvora.hooking import Pointer, bind_hook
from dvora.loader.elf import get_elf_loader
from dvora.loader.elf.loader import ELFLoader
from dvora.machine import Machine, machine_from_elf


class Emulation:
    """Represents a complete Unicorn emulation environment for ELF files
    together with some utility functions.

    The only required parameters are a path to the emulated binary, and a search
    path for the needed libraries.
    """

    # pylint: disable=too-many-instance-attributes
    #: The emulation engine interface (used for running/stopping and setting up
    #: hooks)
    engine: UnicornEngine
    #: The underlying architecture properties
    machine: Machine
    #: Calling conventions
    abi: ABI
    #: ELF loading environment
    loader: ELFLoader
    #: Used for allocating dynamic data in the process and to bind & hook
    #: heap library functions in the emulated process
    heap: Heap

    #: The address at which the main binary has loaded
    load_address: int
    #: Pointer to the thread area (currently only 1 thread is supported)
    thread_area: int
    #: Execution trace: a list of visited instruction addresses
    trace: List[int]
    trace_branches: bool
    trace_all_instructions: bool

    def __init__(self, binary: str, lib_dirs: List[str], where: Optional[int] = None):
        # Instantiate the engine
        self._init_engine(binary)

        # Load the binary (and its dependencies)
        self._load_binary(binary, lib_dirs, where)

        # Only allocate the stack AFTER the binary was loaded (we don't want
        # the stack to occupy memory the loaded binary needs)
        self.engine.init_stack()

        # Set up the heap and its hooks (malloc, free, ...)
        self._setup_heap()

        # Set up the tracer and its configuration
        self._setup_tracer()

        # run some library initialization code
        self._lib_setup()

    def _init_engine(self, binary: str):
        self.machine = machine_from_elf(binary)

        self.engine = UnicornEngine(self.machine)
        self.engine.cpu.init_regs()

        self.abi = get_abi_class(self.machine)(self.engine, self.machine)

    def _load_binary(
        self, binary: str, lib_dirs: List[str], where: Optional[int] = None
    ):
        loader_cls = get_elf_loader(self.machine)
        self.loader = loader_cls(self.engine.vm, self.machine, lib_dirs)
        self.load_address = self.loader.load(binary, where)

        # Set the thread pointer
        self.engine.cpu.set_thread_pointer(self.loader.thread_area_ptr)

        # Hook "__tls_get_addr"
        self.engine.hook(
            self.loader.dlsym("__tls_get_addr"),
            bind_hook(self.abi, self.loader.tls_get_addr),
        )

    def _setup_heap(self):
        self.heap = Heap(self.engine.vm, self.abi)
        heap_adapter = HeapAdapter(self.heap)
        heap_adapter.bind(self.engine, self.abi, self.loader)

    def _setup_tracer(self):
        self.engine.set_tracer(self.tracer)
        self.trace = []
        self.trace_all_instructions = False
        self.trace_branches = False
        self.disassembler = capstone.Cs(
            capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM
        )  # TODO

    def _lib_setup(self):
        __ctype_init_address = self.loader.dlsym("__ctype_init")
        if __ctype_init_address:
            __ctype_init = self.make_function(__ctype_init_address)
            __ctype_init()

    def take_snapshot(self) -> Iterable[Chunk]:
        yield from self.loader.take_snapshot()

        thread_area = self.engine.vm.get_mem(
            self.loader.thread_area_ptr, self.loader.thread_area_size
        )
        yield Chunk(
            address=self.loader.thread_area_ptr,
            data=thread_area,
            protection=PROT_WRITE | PROT_READ,
            label="thread-area",
        )

        dtv = self.engine.vm.get_mem(self.loader.dtv_ptr, self.loader.dtv_size)
        yield Chunk(
            address=self.loader.dtv_ptr,
            data=dtv,
            protection=PROT_WRITE | PROT_READ,
            label="dynamic-thread-vector",
        )

    def tracer(self, address, engine, cpu, vm) -> bool:
        # pylint: disable=unused-argument
        if self.trace_all_instructions:
            self.trace.append(address)
        elif self.trace_branches and self._is_branch(address):
            self.trace.append(address)

        logger.debug(
            f"TRACE: {self.loader.format_address(address)} {'*' if self._is_branch(address) else ''}"
        )

        return False

    def _is_branch(self, address: int) -> bool:
        for d in self.disassembler.disasm(self.engine.vm.get_mem(address, 4), address):
            return d.mnemonic[0] == "b" and not d.mnemonic == "bic"
        return False

    def make_function(self, address: int, timeout_seconds: int = 1):
        """Make a Python wrapper for a native function.

        Args:
            address: The address at which the function starts.
            timeout_seconds: The maximum time that the function is allowed to
                run.

        Returns:
            A callable that will run the function at the specified address.
            The callable's parameters will be translated to the native
            function's parameters according to the ``ABI``.
            Upon successful termination, the callable will return whetever the
            native function returned (again, according to the ``ABI``), or
            ``None`` in case the timeout expired.

        """

        def function_caller(*args):
            # This is a Python wrapper to a native function, so there are only
            # positional arguments.
            self.abi.prepare_function_call(address, args, self.engine.end_addr)
            self.engine.run_context.pc = self.engine.end_addr
            status = self.engine.run(address, timeout_seconds)
            if not status:
                return None
            return self.abi.get_result()

        return function_caller

    def set_breakpoint(self, bp):
        self.engine.breakpoints.add(bp)

    def remove_breakpoint(self, bp):
        self.engine.breakpoints.remove(bp)

    def step(self, n_steps=1, timeout_seconds=1):
        self.engine.run(self.engine.run_context.pc, timeout_seconds, n_steps)

    def cont(self, timeout_seconds=1):
        self.engine.run(self.engine.run_context.pc, timeout_seconds)

    def dump_regs(self):
        self.abi.dump_regs()

    def get_mem(self, addr: int, size: int) -> bytes:
        return self.engine.vm.get_mem(addr, size)

    def set_mem(self, addr: int, content: bytes):
        return self.engine.vm.set_mem(addr, content)

    def read_string(self, addr: int) -> str:
        return cast(str, Pointer(addr, self.engine.vm).read_string().decode())

    def set_reg(self, reg_name: str, reg_val: int) -> None:
        setattr(self.engine.cpu, reg_name, reg_val)

    def get_reg(self, reg_name: str) -> int:
        return cast(int, getattr(self.engine.cpu, reg_name))

    def trace_mode(
        self,
        all_instructions: bool = False,
        branches: bool = False,
        memreads: bool = False,
        memwrites: bool = False,
    ) -> None:
        # pylint: disable=unused-argument
        self.trace_all_instructions = all_instructions
        self.trace_branches = branches

    def clear_trace(self) -> None:
        self.trace = []
