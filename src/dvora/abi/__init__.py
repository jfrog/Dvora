from typing import List, Optional, Type

from dvora.abi.aarch64 import ABIS as ABIS_AARCH64
from dvora.abi.abi import ABI
from dvora.abi.arm import ABIS as ABIS_ARM
from dvora.abi.mips import ABIS as ABIS_MIPS
from dvora.abi.x86 import ABIS as ABIS_X86
from dvora.machine import Machine

ABIS: List[Type[ABI]] = ABIS_X86 + ABIS_ARM + ABIS_MIPS + ABIS_AARCH64


def get_abi_class(machine: Machine) -> Type[ABI]:
    arch_name = machine.name
    for abi_class in ABIS:
        if arch_name in abi_class.arch:
            return abi_class
    raise NotImplementedError(f"No known ABIs for {arch_name}")


__all__ = ["ABIS", "get_abi_class"]
