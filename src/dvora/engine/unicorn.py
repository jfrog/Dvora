"""Implementation of all ``Engine`` components for the unicorn emulator.
"""
from collections import defaultdict
from types import ModuleType
from typing import Callable, ClassVar, Dict, List, Set, Type

import attr
import unicorn
from cached_property import cached_property
from loguru import logger
from unicorn import arm64_const, arm_const, mips_const, x86_const

from dvora.commons import (
    PAGE_SIZE,
    PROT_READ,
    PROT_WRITE,
    STACK_BOTTOM,
    STACK_SIZE,
    align_up,
)
from dvora.engine.engine import (
    CPU,
    Engine,
    MemoryChunk,
    MemoryMap,
    VirtualMemory,
)
from dvora.exceptions import (
    InvalidFetch,
    InvalidMemoryAccess,
    StackOverflow,
    UnimplementedArchitecture,
)

UC_MEM_ACCESS_NAME = {
    16: "UC_MEM_READ",
    17: "UC_MEM_WRITE",
    18: "UC_MEM_FETCH",
    19: "UC_MEM_READ_UNMAPPED",
    20: "UC_MEM_WRITE_UNMAPPED",
    21: "UC_MEM_FETCH_UNMAPPED",
    22: "UC_MEM_WRITE_PROT",
    23: "UC_MEM_READ_PROT",
    24: "UC_MEM_FETCH_PROT",
    25: "UC_MEM_READ_AFTER",
}


@attr.s(auto_attribs=True)
class RunContext:
    pc: int


class UnicornEngine(Engine):
    """Implementation of ``Engine`` for unicorn"""

    # pylint: disable=too-many-instance-attributes
    #: Handle to a unicorn instance
    mu: unicorn.Uc
    #: Mapping from hook address to a list of callbacks. Each callback is
    #: expected to have the following signature:
    #: ``callback(address, engine, cpu, vm)``
    #: If the callback returns ``True``, then it is considered that the hook
    #: has been handled and no other hooks will be called on this address.
    hooks: Dict[int, List[Callable]]
    #: A set of addresses which will cause execution to stop
    breakpoints: Set[int]
    #: The address for which the last memory access error occurred
    fault_address: int
    #: A callback to be run for every instruction. It has the same signature
    #: as those of the hook callback.
    trace_func: Callable

    def __init__(self, machine):
        super().__init__(machine)

        self.run_context = RunContext(0)
        cpu_class = UnicornCPU.available_cpus.get(machine.name, None)
        if not cpu_class:
            raise UnimplementedArchitecture(machine.name)

        arch, mode = cpu_class.UC_ARCH, cpu_class.UC_MODE

        if machine.endianness == "little":
            mode += unicorn.UC_MODE_LITTLE_ENDIAN
        elif machine.endianness == "big":
            mode += unicorn.UC_MODE_BIG_ENDIAN

        self.mu = unicorn.Uc(arch, mode)
        self.vm = UnicornVM(self.mu)
        self.cpu = cpu_class(self.mu)

        self.hooks = defaultdict(list)
        self.breakpoints = set()
        self.fault_address = 0
        self.mu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self.hook_mem_invalid)
        self.mu.hook_add(unicorn.UC_HOOK_INTR, self.hook_intr)
        self.hook_code_uc_handle = None
        self.trace_func = self.default_tracer

    @cached_property
    def end_addr(self) -> int:
        return self.vm.allocate_padded(PAGE_SIZE, PROT_READ)

    def _install_hook_code(self):
        self.hook_code_uc_handle = self.mu.hook_add(
            unicorn.UC_HOOK_CODE, self.hook_code, user_data=self.run_context
        )

    def hook(self, address, handler):
        if not self.hooks:
            self._install_hook_code()
        self.hooks[address].append(handler)

    def unhook(self, address: int):
        self.hooks.pop(address)
        if not self.hooks:
            self.mu.hook_del(self.hook_code_uc_handle)
            self.hook_code_uc_handle = None

    @staticmethod
    def default_tracer(
        address: int, engine: Engine, cpu: CPU, vm: VirtualMemory
    ) -> bool:
        # pylint: disable=unused-argument
        return True

    def set_tracer(self, trace_func):
        if not self.hook_code_uc_handle:
            self._install_hook_code()
        self.trace_func = trace_func

    def hook_code(self, mu, address, size, user_data):
        # pylint: disable=unused-argument
        user_data.pc = address
        if self.trace_func(address, self, self.cpu, self.vm):
            return True

        if address in self.breakpoints:
            self.mu.emu_stop()
            return False

        for handler in self.hooks[address]:
            if handler(address, self, self.cpu, self.vm):
                return True
        return False

    def hook_intr(self, uc, intno, user_data):
        # pylint: disable=unused-argument
        logger.info(f"hook_intr({intno}), pc={hex(self.pc)}")
        if intno == 2:
            return True
        return False

    def hook_mem_invalid(self, uc, access, address, size, value, user_data):
        # pylint: disable=unused-argument, too-many-arguments
        if address == self.end_addr:
            return True

        logger.info(
            f"MEM_UNMAPPED(access={UC_MEM_ACCESS_NAME[access]}, {hex(address)}, {size}, {value})"
        )
        self.fault_address = address

        return False

    def run(self, address: int, timeout_seconds: int, n_steps: int = 0) -> bool:
        timeout_us = timeout_seconds * unicorn.UC_SECOND_SCALE  # us=microseconds
        try:
            self.mu.emu_start(address, self.end_addr, timeout_us, count=n_steps)
        except unicorn.UcError as uc_error:
            if self.pc != self.end_addr:
                logger.warning(f"UcError {uc_error} at addr = {hex(self.pc)}")
                if uc_error.errno in (
                    unicorn.UC_ERR_READ_UNMAPPED,
                    unicorn.UC_ERR_WRITE_UNMAPPED,
                ):
                    if (
                        (STACK_BOTTOM + STACK_SIZE)
                        <= self.fault_address
                        < (STACK_BOTTOM + STACK_SIZE + PAGE_SIZE)
                    ):
                        raise StackOverflow(self.fault_address) from uc_error
                    raise InvalidMemoryAccess(self.fault_address) from uc_error
                if uc_error.errno == unicorn.UC_ERR_FETCH_UNMAPPED:
                    raise InvalidFetch(self.fault_address) from uc_error
                return False
        except Exception as error:
            logger.exception(error)
            return False
        finally:
            self.mu.emu_stop()

        return True


class UnicornCPU(CPU):
    # name -> Uc value
    REGISTERS: ClassVar[Dict[str, int]]

    # Uc architecture and mode
    UC_ARCH: ClassVar[int]
    UC_MODE: ClassVar[int]

    # (arch, attrib) -> CPU class
    available_cpus: Dict[str, Type["UnicornCPU"]] = {}

    mu: unicorn.Uc

    def __init__(self, mu):
        self.mu = mu

    def init_regs(self):
        for reg in self.REGISTERS.values():
            self.mu.reg_write(reg, 0)

    def __setattr__(self, name: str, value: int):
        if name in self.REGISTERS:
            self.mu.reg_write(self.REGISTERS[name], value)
        else:
            super().__setattr__(name, value)

    def __getattr__(self, name: str) -> int:
        if name in self.REGISTERS:
            return int(self.mu.reg_read(self.REGISTERS[name]))

        raise AttributeError

    def get_gpreg(self):
        return {
            reg_name: self.mu.reg_read(reg_uc_id)
            for reg_name, reg_uc_id in self.REGISTERS.items()
        }

    def set_gpreg(self, values):
        for reg_name, reg_value in values.items():
            self.mu.reg_write(self.REGISTERS[reg_name], reg_value)

    @classmethod
    def register(cls, arch):
        UnicornCPU.available_cpus[arch] = cls


class UnicornVM(VirtualMemory):
    def __init__(self, mu):
        super().__init__()
        self.mu = mu

    def add_memory_page(self, addr: int, access: int, item_str: bytes, name: str = ""):
        size = align_up(len(item_str), PAGE_SIZE)

        for mm in self.mappings:
            if mm.addr <= addr < mm.addr + mm.size:
                self.set_mem(addr, item_str)
                return

        self.mappings.append(MemoryMap(addr, size, name, access))

        self.mu.mem_map(addr, size)
        self.set_mem(addr, item_str)

    def get_mem(self, addr: int, size: int) -> bytes:
        return bytes(self.mu.mem_read(addr, size))

    def set_mem(self, addr: int, content: bytes):
        self.mu.mem_write(addr, content)

    def get_all_memory(self) -> Dict[int, MemoryChunk]:
        chunks = {}
        for mm in self.mappings:
            data = self.get_mem(mm.addr, mm.size)
            chunks[mm.addr] = MemoryChunk(mm.access, len(data), data)

        return chunks

    def is_mapped(self, address: int, size: int):
        for addr in range(address, address + size):
            for mm in self.mappings:
                if mm.addr <= addr < mm.addr + mm.size:
                    break
            else:
                return False
        return True

    def restore_mem_state(self, mem_state: Dict[int, MemoryChunk]):
        """Restore the memory state according to mem_state
        Optimisation: only consider memory unwrittable"""
        new_mappings: List[MemoryMap] = []
        addrs = set()

        for mm in self.mappings:
            if mm.addr not in mem_state:
                # Remove additionnal maps
                self.mu.mem_unmap(mm.addr, mm.size)
            else:
                # Rewrite map content
                if mm.access & PROT_WRITE:
                    self.set_mem(mm.addr, mem_state[mm.addr].data)
                new_mappings.append(mm)
                addrs.add(mm.addr)

        for addr, chunk in mem_state.items():
            # Add missing pages
            if addr not in addrs:
                self.mu.mem_map(addr, chunk.size)
                self.set_mem(addr, chunk.data)
                new_mappings.append(MemoryMap(addr, chunk.size, "", chunk.access))

        self.mappings = new_mappings


def get_register_mapping(const_module: ModuleType, prefix: str) -> Dict[str, int]:
    return {
        name[len(prefix) :]: getattr(const_module, name)
        for name in dir(const_module)
        if name.startswith(prefix)
    }


class UnicornCPU_x86(UnicornCPU):
    UC_ARCH = unicorn.UC_ARCH_X86
    UC_MODE = unicorn.UC_MODE_32

    # TODO: The registers for x86 and x64 are all in the same x86_const module.
    # Find a way to untangle them so that they can be used to generate a
    # register dictionary via `get_register_mapping`.
    # TODO: There's overlap between registers in x86. So when taking a register
    # snapshot, we need to make sure we only take the "widest" registers:
    # EAX for x86, RAX for x64.
    # This table summarizes this nicely:
    #  https://en.wikipedia.org/wiki/X86#/media/File:Table_of_x86_Registers_svg.svg
    # XXX: There are however some registers that are not implemented in unicorn,
    # such as RFLAGS and it's smaller brother FLAGS (only EFLAGS exists)

    REGISTERS = {
        "EAX": x86_const.UC_X86_REG_EAX,
        "EBX": x86_const.UC_X86_REG_EBX,
        "ECX": x86_const.UC_X86_REG_ECX,
        "EDI": x86_const.UC_X86_REG_EDI,
        "EDX": x86_const.UC_X86_REG_EDX,
        "ESI": x86_const.UC_X86_REG_ESI,
        "EBP": x86_const.UC_X86_REG_EBP,
        "ESP": x86_const.UC_X86_REG_ESP,
        "EIP": x86_const.UC_X86_REG_EIP,
    }


class UnicornCPU_x86_64(UnicornCPU):
    UC_ARCH = unicorn.UC_ARCH_X86
    UC_MODE = unicorn.UC_MODE_64

    REGISTERS = {
        "RAX": x86_const.UC_X86_REG_RAX,
        "RBX": x86_const.UC_X86_REG_RBX,
        "RCX": x86_const.UC_X86_REG_RCX,
        "RDI": x86_const.UC_X86_REG_RDI,
        "RDX": x86_const.UC_X86_REG_RDX,
        "RSI": x86_const.UC_X86_REG_RSI,
        "RBP": x86_const.UC_X86_REG_RBP,
        "RSP": x86_const.UC_X86_REG_RSP,
        "R8": x86_const.UC_X86_REG_R8,
        "R11": x86_const.UC_X86_REG_R11,
        "R9": x86_const.UC_X86_REG_R9,
        "R10": x86_const.UC_X86_REG_R10,
        "R12": x86_const.UC_X86_REG_R12,
        "R13": x86_const.UC_X86_REG_R13,
        "R14": x86_const.UC_X86_REG_R14,
        "R15": x86_const.UC_X86_REG_R15,
        "RIP": x86_const.UC_X86_REG_RIP,
        "FS_BASE": x86_const.UC_X86_REG_FS_BASE,
    }

    def set_thread_pointer(self, thread_pointer: int) -> None:
        # pylint: disable=attribute-defined-outside-init
        self.FS_BASE = thread_pointer


class UnicornCPU_arm(UnicornCPU):
    UC_ARCH = unicorn.UC_ARCH_ARM
    UC_MODE = unicorn.UC_MODE_ARM

    REGISTERS = get_register_mapping(arm_const, "UC_ARM_REG_")
    # TPIDRURO is an alias to this coprocessor register
    REGISTERS["TPIDRURO"] = arm_const.UC_ARM_REG_C13_C0_3

    def init_regs(self):
        super().init_regs()
        # VFP is not in QEMU by default. The following coprocessor manipulation
        # turns it on
        coprocessor_access_control = self.mu.reg_read(arm_const.UC_ARM_REG_C1_C0_2)
        # Sets full control to coprocessors #10 & #11 (bits 20-21 and 22-23 in
        # the "Coprocessor Access Control Register"
        coprocessor_access_control |= 0xF << 20
        self.mu.reg_write(arm_const.UC_ARM_REG_C1_C0_2, coprocessor_access_control)
        self.mu.reg_write(arm_const.UC_ARM_REG_FPEXC, 0x40000000)

    def set_thread_pointer(self, thread_pointer: int) -> None:
        # pylint: disable=attribute-defined-outside-init
        self.TPIDRURO = thread_pointer


class UnicornCPU_armt(UnicornCPU):
    UC_ARCH = unicorn.UC_ARCH_ARM
    UC_MODE = unicorn.UC_MODE_THUMB

    REGISTERS = get_register_mapping(arm_const, "UC_ARM_REG_")


class UnicornCPU_mips(UnicornCPU):
    UC_ARCH = unicorn.UC_ARCH_MIPS
    UC_MODE = unicorn.UC_MODE_MIPS32

    REGISTERS = get_register_mapping(mips_const, "UC_MIPS_REG_")
    # "CPR0_x" are aliases to "x" (for x in 0 to 31)
    for r in range(32):
        REGISTERS[f"CPR0_{r}"] = REGISTERS[str(r)]
    # "R_{HI,LO}" are aliases to "HI,LO"
    REGISTERS["R_HI"] = REGISTERS["HI"]
    REGISTERS["R_LO"] = REGISTERS["LO"]


class UnicornCPU_aarch64(UnicornCPU):
    UC_ARCH = unicorn.UC_ARCH_ARM64
    UC_MODE = unicorn.UC_MODE_ARM

    REGISTERS = get_register_mapping(arm64_const, "UC_ARM64_REG_")


UnicornCPU_x86.register("x86")
UnicornCPU_x86_64.register("x86_64")
UnicornCPU_arm.register("arm")
UnicornCPU_armt.register("armt")
UnicornCPU_mips.register("mips")
UnicornCPU_aarch64.register("aarch64")
