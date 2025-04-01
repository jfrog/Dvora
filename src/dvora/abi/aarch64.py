from typing import ClassVar, List, Optional, Type

from loguru import logger
from more_itertools import grouper

from dvora.abi.abi import ABI


class ABIAArch64(ABI):
    regs_mapping: ClassVar[List[str]] = ["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]
    ret_reg_name: ClassVar[str] = "X0"
    arch: ClassVar[List[str]] = ["aarch64"]

    def set_ret(self, ret_addr: int):
        self.engine.cpu.LR = ret_addr

    def get_ret(self) -> int:
        return self.engine.cpu.LR

    def ret(self, retaddr: int, retval: Optional[int] = None):
        if retval is not None:
            retval = self.machine.unsigned(retval)
            setattr(self.engine.cpu, self.ret_reg_name, retval)
        self.engine.cpu.PC = retaddr

    def dump_regs(self):
        regs = [f"X{i}" for i in range(32)]
        regs.extend(["SP", "LR", "PC"])
        for line in grouper(regs, 4):
            logger.info(
                "\t".join(f"{r:<3}=0x{getattr(self.engine.cpu, r):016x}" for r in line)
            )

    def dump_stacktrace(self):
        pass


ABIS: List[Type[ABI]] = [ABIAArch64]
