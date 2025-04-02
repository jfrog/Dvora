import secrets
from abc import ABC, abstractmethod
from typing import ClassVar, List

from dvora.abi import ABI
from dvora.engine import Engine
from dvora.exceptions import InvalidMemoryAccess, ProbeTimeout
from dvora.heap import Heap


class Function:
    NAME: ClassVar[str] = ""
    PARAM_DEREFS: ClassVar[List[int]] = []  # The number of "*" each parameter has
    PROBES: ClassVar["ProbeSet"]

    engine: Engine
    abi: ABI
    heap: Heap

    reset_mem: bool
    address: int
    timeout_seconds: int

    def __init__(self, engine, abi, heap):
        self.engine = engine
        self.abi = abi
        self.reset_mem = True
        self.heap = heap

    def reset_full(self):
        """Reset between two functions"""
        self.heap.reset()

    def reset(self):
        """Reset between two probes"""
        self.reset_full()

    def set_probe_address(self, address):
        self.address = address

    def set_timeout(self, timeout_seconds):
        self.timeout_seconds = timeout_seconds

    def alloc_bytes(self, mem: bytes) -> int:
        return self.heap.alloc(mem)

    def alloc_mem(self, size: int) -> int:
        mem = secrets.token_bytes(size)
        return self.alloc_bytes(mem)

    # TODO: Maybe string should actually be an "str", and _alloc_string should convert it to "bytes"
    def alloc_string(self, string: bytes):
        return self.alloc_bytes(string + b"\x00")

    def alloc_pointer(self, pointer: int) -> int:
        return self.alloc_bytes(self.abi.machine.pack_word(pointer))

    def write_mem(self, addr: int, element: bytes):
        self.engine.vm.set_mem(addr, element)

    # TODO: element should be a string
    def write_string(self, addr: int, element: bytes):
        self.write_mem(addr, element + b"\x00")

    def call(self, *args):
        self.abi.prepare_function_call(self.address, args, self.engine.end_addr)
        status = self.engine.run(self.address, self.timeout_seconds)
        if not status:
            raise ProbeTimeout()
        return self.abi.get_result()

    def memcmp(self, addr: int, element: bytes):
        """Compare the memory at `addr` to `element`.
        The number of compared bytes is `len(element)`"""
        try:
            return self.engine.vm.get_mem(addr, len(element)) == element
        except RuntimeError:
            return False

    def signed(self, element: int) -> int:
        return self.abi.machine.signed(element)

    def unsigned(self, element: int) -> int:
        return self.abi.machine.unsigned(element)

    def read_pointer(self, addr):
        pointer_size = self.abi.machine.sizeof_word
        try:
            element = self.engine.vm.get_mem(addr, pointer_size)
        except RuntimeError:
            return False
        return self.abi.machine.unpack_word(element)

    def probe_harness(self, probe_func) -> bool:
        self.engine.restore_snapshot(memory=self.reset_mem)
        self.reset()

        try:
            ret = bool(probe_func(self))
        except ProbeTimeout:
            self.reset_mem = True
            return False
        except InvalidMemoryAccess:
            return False

        return ret

    def execute(self, address: int, timeout_seconds=0) -> bool:
        self.set_probe_address(address)
        self.set_timeout(timeout_seconds)

        return self.PROBES.execute(self)


class ProbeSet(ABC):
    def __and__(self, ts: "ProbeSet"):
        return ProbeSetAnd(self, ts)

    def __or__(self, ts: "ProbeSet"):
        return ProbeSetOr(self, ts)

    @abstractmethod
    def execute(self, function: Function) -> bool:
        return False


class ProbeSetAnd(ProbeSet):
    def __init__(self, ts1: ProbeSet, ts2: ProbeSet):
        super().__init__()
        self._ts1 = ts1
        self._ts2 = ts2

    def execute(self, function: Function) -> bool:
        if not self._ts1.execute(function):
            # Shortcircuit
            return False
        return self._ts2.execute(function)


class ProbeSetOr(ProbeSet):
    def __init__(self, ts1: ProbeSet, ts2: ProbeSet):
        super().__init__()
        self._ts1 = ts1
        self._ts2 = ts2

    def execute(self, function: Function) -> bool:
        if self._ts1.execute(function):
            # Shortcircuit
            return True
        return self._ts2.execute(function)


class Probe(ProbeSet):
    def __init__(self, probe_func):
        super().__init__()
        self._probe_func = probe_func

    def execute(self, function: Function):
        return function.probe_harness(self._probe_func)
