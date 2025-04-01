from typing import ClassVar, List, Optional, Type

from dvora.abi.abi import ABI


class ABI_MIPS(ABI):
    regs_mapping: ClassVar[List[str]] = ["A0", "A1", "A2", "A3"]
    ret_reg_name: ClassVar[str] = "V0"
    arch: ClassVar[List[str]] = ["mips"]

    def set_ret(self, ret_addr: int):
        self.engine.cpu.RA = ret_addr

    def get_ret(self) -> int:
        return self.engine.cpu.RA

    def ret(self, retaddr: int, retval: Optional[int] = None):
        pass

    def dump_regs(self):
        pass

    def dump_stacktrace(self):
        pass

    def prepare_function_call(
        self, address: int, args: List[int], end_addr: int
    ) -> None:
        self.engine.cpu.T9 = address
        # From the MIPS ELF ABI reference document, chapter "The Stack Frame":
        #   "Function call argument area. In a non-leaf function the maximum
        #    numbers of bytes of arguments used to call other functions from the
        #    non leaf function must be allocated. Hoewever, at least four words
        #    (16 bytes) must always be reserved, even if the maximum number of
        #    arguments to any called function is fewer than four words."
        excess = 0
        if len(args) <= 4:
            excess = 4 * self.machine.sizeof_word
        elif len(args) < 8:
            excess = (8 - len(args)) * self.machine.sizeof_word
        self.engine.cpu.SP -= excess
        super().prepare_function_call(address, args, end_addr)


ABIS: List[Type[ABI]] = [ABI_MIPS]
