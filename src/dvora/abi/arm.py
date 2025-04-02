from typing import ClassVar, Iterable, List, Optional, Type

from loguru import logger
from more_itertools import grouper, pairwise

from dvora.abi.abi import ABI
from dvora.commons import STACK_BOTTOM, STACK_SIZE
from dvora.exceptions import CorruptedFrame


class StackFrame:
    abi: ABI
    lr: int
    fp: int

    def __init__(self, abi: ABI, lr: int, fp: int):
        self.abi = abi
        self.lr = lr
        self.fp = fp

    @property
    def sizeof_word(self) -> int:
        return self.abi.machine.sizeof_word

    def read_word(self, address: int) -> int:
        return self.abi.read_word(address)

    @property
    def function_address(self) -> int:
        address = self.read_word(self.fp - self.sizeof_word)
        # PC is saved in the second instruction of the prologue, so subtract
        address -= self.sizeof_word * 3
        return address

    def up(self) -> "StackFrame":
        fp = self.read_word(self.fp - self.sizeof_word * 4)
        fp += self.sizeof_word
        if not STACK_BOTTOM <= fp <= (STACK_BOTTOM + STACK_SIZE):
            raise CorruptedFrame()
        lr = self.read_word(fp - self.sizeof_word * 2)
        return StackFrame(self.abi, lr, fp)

    def unwind(self) -> Iterable["StackFrame"]:
        frame = self
        while True:
            yield frame
            try:
                frame = frame.up()
            except CorruptedFrame:
                break


class ABI_ARM(ABI):
    regs_mapping: ClassVar[List[str]] = ["R0", "R1", "R2", "R3"]
    ret_reg_name: ClassVar[str] = "R0"
    arch: ClassVar[List[str]] = ["arm", "armt"]

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
        regs = [f"R{i}" for i in range(13)]
        regs.extend(["SP", "LR", "PC"])
        for line in grouper(regs, 4):
            logger.info(
                "\t".join(f"{r:<3}=0x{getattr(self.engine.cpu, r):08x}" for r in line)
            )

    def dump_stacktrace(self):
        pc = self.engine.pc
        lr = self.engine.cpu.LR
        fp = self.engine.cpu.R12

        frames = list(StackFrame(self, lr, fp).unwind())

        logger.info("Stacktrace:")
        function_address = frames[0].function_address
        logger.info(
            f"    {hex(pc)} ({hex(function_address)} + {hex(pc - function_address)})"
        )
        for frame, prev in pairwise(frames):
            lr = frame.lr
            function_address = prev.function_address
            logger.info(
                f"    {hex(lr)} ({hex(function_address)} + {hex(lr - function_address)})"
            )


ABIS: List[Type[ABI]] = [ABI_ARM]
