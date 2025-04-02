from typing import Type

from dvora.exceptions import LoaderNotImplemented
from dvora.loader.elf.elf32loader import (
    ARM32ELFLoader,
    MIPS32ELFLoader,
    X86ELFLoader,
)
from dvora.loader.elf.elf64loader import AArch64ELFLoader, X64ELFLoader
from dvora.loader.elf.loader import ELFLoader
from dvora.machine import Machine


def get_elf_loader(machine: Machine) -> Type[ELFLoader]:
    if machine.name == "arm":
        if machine.bit_width == 32:
            return ARM32ELFLoader
    elif machine.name == "x86_64":
        if machine.bit_width == 64:
            return X64ELFLoader
    elif machine.name == "x86":
        if machine.bit_width == 32:
            return X86ELFLoader
    elif machine.name == "aarch64":
        return AArch64ELFLoader
    elif machine.name == "mips":
        return MIPS32ELFLoader
    raise LoaderNotImplemented(machine)
