"""Implementation of ELF loaders for ARM32.

Examples:
    >>> loader = ARM32ELFLoader(engine.vm, machine, ["/lib", "/usr/lib"])
    >>> loader.load("/bin/httpd", 0x123000)
    1191936
    >>> malloc = loader.dlsym("malloc")
    >>> malloc
    540056
    >>> loader.format_address(malloc)
    libc.6.so::0x73d98
    >>> for address, data in loader.take_snapshot():
        ...
"""

# Relocation codenames glossary:
# A:   Represents the addend used to compute the value of the relocatable field.
# AHL: Identifies another type of addend used to compute the value of the
#      relocatable field.
# P:   Represents the place (section offset or address) of the storage unit
#      being relocated (computed using r_offset).
# S:   Represents the value of the symbol whose index resides in the relocation
#      entry, unless the the symbol is STB_LOCAL and is of type STT_SECTION in
#      which case S represents the original sh_addr minus the final sh_addr.
# G:   Represents the offset into the global offset table at which the address
#      of the relocation entry symbol resides during execution.
# GP:  Represents the final gp value to be used for the relocatable, executable,
#      or shared object file being produced.
# EA:  Represents the effective address of the symbol prior to relocation.
# L:   Represents the .lit4 or .lit8 literal table offset. Prior to relocation
#      the addend field of a literal reference contains the offset into the
#      global data area. During relocation, each literal section from each
#      contributing file is merged and sorted, after which duplicate entries
#      are removed and the section compressed, leaving only unique entries.
#      The relocation factor L is the mapping from the old offset of the
#      original gp to the value of gp used in the final file.

import os
from enum import IntEnum
from itertools import count, islice
from typing import Iterator, List, Optional

from loguru import logger

from dvora.commons import PAGE_SIZE, PROT_EXEC, PROT_READ, VECTORS_START, Chunk
from dvora.engine import VirtualMemory
from dvora.loader.base import LoadCommand
from dvora.loader.elf.loader import ELFLoader, LibraryInfo
from dvora.machine import Machine


class ARM32RelocationTypes(IntEnum):
    R_ARM_TLS_DTPMOD32 = 17
    R_ARM_TLS_DTPOFF32 = 18
    R_ARM_TLS_TPOFF32 = 19


class ARM32ELFLoader(ELFLoader):
    """An ELF loader that specializes in ARM32 ELF binaries.
    The specialization comes in the form of relocation types that are ARM32
    specific.
    """

    def __init__(
        self,
        vm: VirtualMemory,
        machine: Machine,
        ld_library_paths: Optional[List[str]] = None,
    ):
        super().__init__(vm, machine, ld_library_paths)

        self.load_vectors()

    def load_vectors(self):
        """Find the "vectors" file in the library search path and load it at
        VECTORS_START.
        """
        for path in self.ld_library_paths:
            for candidate_library in os.listdir(path):
                if candidate_library == "vectors":

                    load_command = LoadCommand(
                        start=0,
                        end=PAGE_SIZE,
                        flags=PROT_READ | PROT_EXEC,
                        file_page_start=0,
                        alignment=1,
                    )
                    vectors_path = os.path.join(path, candidate_library)
                    with open(vectors_path, "rb") as vectors_file:
                        load_command.load(vectors_file, self.vm, VECTORS_START)
                    break

    def take_snapshot(self) -> Iterator[Chunk]:
        yield from super().take_snapshot()
        # Dump the vectors page
        yield Chunk(
            address=VECTORS_START,
            data=self.vm.get_mem(VECTORS_START, PAGE_SIZE),
            protection=PROT_READ | PROT_EXEC,
            label="vectors",
        )

    @staticmethod
    def reloc_module_id(
        loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
    ) -> bool:
        if rel["r_info_sym"] != 0:
            # Resolves to the module number of the module defining the specified
            # symbol
            sym = libinfo.get_symbol(rel["r_info_sym"])
            if sym.name not in loader.tls_symbols:
                logger.warning(f"Ignoring TLS data relocation for {sym.name}")
            else:
                defining_lib_name, _ = loader.tls_symbols[sym.name]
                defining_lib_info = loader.libraries[defining_lib_name]
                loader.write_word(address, defining_lib_info.lib_id)
        else:
            # Resolves to the module number of the current module
            loader.write_word(address, libinfo.lib_id)
        return True

    @staticmethod
    def reloc_offset_in_tls(
        loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
    ) -> bool:
        # Resolves to the offset of the specified TLS symbol within its TLS
        # block
        sym = libinfo.get_symbol(rel["r_info_sym"])
        _, defining_symbol = loader.tls_symbols[sym.name]
        loader.write_word(address, defining_symbol["st_value"])
        return True

    @staticmethod
    def reloc_offset_in_thread_area(
        loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
    ) -> bool:
        if rel["r_info_sym"] != 0:
            # Resolves to the offset of the specified symbol from the thread
            # pointer
            sym = libinfo.get_symbol(rel["r_info_sym"])
            defining_lib_name, defining_symbol = loader.tls_symbols[sym.name]
            if sym.name not in loader.tls_symbols:
                logger.warning(f"Ignoring TLS data relocation for {sym.name}")
            else:
                defining_lib_info = loader.libraries[defining_lib_name]
                value = defining_lib_info.tls_offset + defining_symbol["st_value"]
                loader.write_word(address, value)
        else:
            # Resolves to the offset of the current module's TLS block
            value = loader.read_word(address) + libinfo.tls_offset
            loader.write_word(address, value)
        return True


ARM32ELFLoader.register_relocator(
    ARM32RelocationTypes.R_ARM_TLS_DTPMOD32, ARM32ELFLoader.reloc_module_id
)
ARM32ELFLoader.register_relocator(
    ARM32RelocationTypes.R_ARM_TLS_DTPOFF32, ARM32ELFLoader.reloc_offset_in_tls
)
ARM32ELFLoader.register_relocator(
    ARM32RelocationTypes.R_ARM_TLS_TPOFF32, ARM32ELFLoader.reloc_offset_in_thread_area
)


class X86ELFLoader(ELFLoader):
    """An ELF loader that specializes in x86 ELF binaries.
    The specialization comes in the form of relocation types that are x86
    specific.
    """


class X86RelocationTypes(IntEnum):
    R_386_32 = 1
    R_386_GLOB_DAT = 6
    R_386_JMP_SLOT = 7
    R_386_RELATIVE = 8


def direct_32(loader: ELFLoader, address: int, rel, libinfo: LibraryInfo) -> bool:
    """ Relocation formula: S """
    if rel["r_info_sym"] != 0:
        # Resolves to the address of the specified symbol
        sym = libinfo.get_symbol(rel["r_info_sym"])
        bound = loader.symbols.get(sym.name)
        if bound:
            symbol_base, defining_symbol = bound
            value = symbol_base + defining_symbol["st_value"]
            loader.write_word(address, value)
        else:
            if sym["st_info"]["bind"] == "STB_WEAK":
                # If the symbol binding is weak, it's ok that we did not
                # find it. However, it could also be that the needed library
                # that contains the symbol was not loaded, and we don't
                # want to fail the load for that.
                # It's better to just issue a warning in the log and move on
                logger.warning(f"Ignoring direct relocation for {sym.name}")
            else:
                return False
    else:
        value = loader.read_word(address)
        loader.write_word(address, value + libinfo.start)
    return True


def create_got_entry(
    loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
) -> bool:
    """ Relocation formula: S """
    return direct_32(loader, address, rel, libinfo)


def create_plt_entry(
    loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
) -> bool:
    """ Relocation formula: S """
    return direct_32(loader, address, rel, libinfo)


def adjust_by_program_base(
    loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
) -> bool:
    # pylint: disable=unused-argument
    value = loader.read_word(address)
    value += libinfo.start
    loader.write_word(address, value)
    return True


X86ELFLoader.register_relocator(X86RelocationTypes.R_386_32, direct_32)
X86ELFLoader.register_relocator(X86RelocationTypes.R_386_GLOB_DAT, create_got_entry)
X86ELFLoader.register_relocator(X86RelocationTypes.R_386_JMP_SLOT, create_plt_entry)
X86ELFLoader.register_relocator(
    X86RelocationTypes.R_386_RELATIVE, adjust_by_program_base
)


class MIPS32ELFLoader(ELFLoader):
    """An ELF loader that specializes in MIPS32 ELF binaries.
    The specialization comes in the form of relocation types that are MIPS32
    specific.
    """

    def relocate_local_got_entries(self, targets: Iterator[int], libinfo: LibraryInfo):
        local_gotno, _ = libinfo.dynamic.get_table_offset("DT_MIPS_LOCAL_GOTNO")

        if not local_gotno:
            return

        for address in islice(targets, local_gotno):
            value = self.read_word(address)
            self.write_word(address, value + libinfo.start)

    def relocate_symbol_got_entries(self, targets: Iterator[int], libinfo: LibraryInfo):
        gotsym, _ = libinfo.dynamic.get_table_offset("DT_MIPS_GOTSYM")
        symtabno, _ = libinfo.dynamic.get_table_offset("DT_MIPS_SYMTABNO")
        if not gotsym or not symtabno:
            return

        for address, sym in zip(
            targets, libinfo.iter_symbol_range(gotsym, symtabno + 1)
        ):
            value = self.read_word(address)
            if sym["st_shndx"] in (
                "SHN_UNDEF",
                "SHN_COMMON",
            ):
                if sym.name in self.symbols:
                    symbol_base, defining_symbol = self.symbols[sym.name]
                    value = symbol_base + defining_symbol["st_value"]
                    self.write_word(address, value)
            elif sym["st_info"]["type"] == "STT_FUNC" and value != sym["st_value"]:
                self.write_word(address, value + libinfo.start)
            elif sym["st_info"]["type"] == "STT_SECTION":
                if sym["st_other"]:
                    self.write_word(address, value + libinfo.start)
            else:
                if sym.name in self.symbols:
                    symbol_base, defining_symbol = self.symbols[sym.name]
                    value = symbol_base + defining_symbol["st_value"]
                    self.write_word(address, value)

    def elf_machine_before_rtld_reloc(self, libinfo: LibraryInfo):
        """From the ELF MIPS ABI reference:

        The global offset table is split into two logically separate
        subtables: locals and externals. Local entries reside in the first
        part of the global offset table. The value of the dynamic tag
        ``DT_MIPS_LOCAL_GOTNO`` holds the number of local global offset
        table entries. These entries only require relocation if they occur
        in a shared object and the shared object memory load address differs
        from the virtual address of the loadable segments of the shared
        object. As with defined external entries in the global offset
        table, these local entries contain actual addresses.
        """

        got, _ = libinfo.dynamic.get_table_offset("DT_PLTGOT")
        if not got:
            return

        targets = count(libinfo.start + got, self.machine.sizeof_word)

        self.relocate_local_got_entries(targets, libinfo)
        self.relocate_symbol_got_entries(targets, libinfo)


class MIPS32RelocationTypes(IntEnum):
    R_MIPS_NONE = 0
    R_MIPS_REL32 = 3


def ignore(loader: ELFLoader, address: int, rel, libinfo: LibraryInfo) -> bool:
    # pylint: disable=unused-argument
    return True


MIPS32ELFLoader.register_relocator(MIPS32RelocationTypes.R_MIPS_NONE, ignore)
MIPS32ELFLoader.register_relocator(MIPS32RelocationTypes.R_MIPS_REL32, direct_32)
