from typing import ClassVar, List, Optional, Type

from dvora.abi.abi import ABI


class ABIRegsStack_x86(ABI):
    ret_reg_name: ClassVar[str] = "RAX"

    def set_ret(self, ret_addr: int):
        self.vm_push(ret_addr)

    def get_ret(self) -> int:
        return 0

    def ret(self, retaddr: int, retval: Optional[int] = None):
        pass

    def dump_regs(self):
        pass

    def dump_stacktrace(self):
        pass


class ABIStdCall_x86(ABIRegsStack_x86):
    ret_reg_name: ClassVar[str] = "EAX"

    regs_mapping: ClassVar[List[str]] = []  # Stack only
    arch: ClassVar[List[str]] = ["x86"]


class ABIFastCall_x86(ABIRegsStack_x86):

    regs_mapping: ClassVar[List[str]] = ["ECX", "EDX"]
    arch: ClassVar[List[str]] = ["x86"]


class ABI_AMD64_SYSTEMV(ABIRegsStack_x86):

    regs_mapping: ClassVar[List[str]] = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]
    arch: ClassVar[List[str]] = ["x86_64"]


class ABI_AMD64_MS(ABIRegsStack_x86):

    regs_mapping: ClassVar[List[str]] = ["RCX", "RDX", "R8", "R9"]
    arch: ClassVar[List[str]] = ["x86_64"]

    def set_ret(self, ret_addr: int):
        # Shadow stack reservation: 0x20 bytes
        for _ in range(4):
            self.vm_push(0)
        super().set_ret(ret_addr)


ABIS: List[Type[ABI]] = [
    ABIStdCall_x86,
    ABIFastCall_x86,
    ABI_AMD64_SYSTEMV,
    ABI_AMD64_MS,
]
