"""Implementation of ELF loaders for x86_64."""

from enum import IntEnum

from loguru import logger

from dvora.loader.elf.loader import ELFLoader, LibraryInfo

# 64bit relocation handlers


def direct_64(loader: ELFLoader, address: int, rel, libinfo: LibraryInfo) -> bool:
    """ S + A """
    if rel["r_info_sym"] != 0:
        # Resolves to the address of the specified symbol
        sym = libinfo.get_symbol(rel["r_info_sym"])
        bound = loader.symbols.get(sym.name)
        if bound:
            symbol_base, defining_symbol = bound
            value = symbol_base + defining_symbol["st_value"]
            value += rel["r_addend"]
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
    """ S + A """
    return direct_64(loader, address, rel, libinfo)


def create_plt_entry(
    loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
) -> bool:
    """ S + A """
    return direct_64(loader, address, rel, libinfo)


def adjust_by_program_base(
    loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
) -> bool:
    """ B + A """
    value = libinfo.start + rel["r_addend"]
    loader.write_word(address, value)
    return True


def dynamic_copy(loader: ELFLoader, address: int, rel, libinfo: LibraryInfo) -> bool:
    """ Copy value of dynamic symbol """
    if rel["r_info_sym"] != 0:
        # Resolves to the address of the specified symbol
        sym = libinfo.get_symbol(rel["r_info_sym"])
        try:
            symbol_base, defining_symbol = loader.symbols[sym.name]
        except KeyError:
            if sym["st_info"]["bind"] != "STB_WEAK":
                # If the symbol binding is weak, it's ok that we did not
                # find it. However, it could also be that the needed library
                # that contains the symbol was not loaded, and we don't
                # want to fail the load for that.
                # It's better to just issue a warning in the log and move on
                logger.warning(f"Ignoring copy relocation for {sym.name}")
        else:
            source = symbol_base + defining_symbol["st_value"]
            data = loader.vm.get_mem(source, defining_symbol["st_size"])
            loader.vm.set_mem(address, data)
    return True


def reloc_offset_in_thread_area(
    loader: ELFLoader, address: int, rel, libinfo: LibraryInfo
) -> bool:
    if rel["r_info_sym"] != 0:
        # Resolves to the offset of the specified symbol from the thread
        # pointer
        sym = libinfo.get_symbol(rel["r_info_sym"])
        defining_lib_name, defining_symbol = loader.tls_symbols[sym.name]
        defining_lib_info = loader.libraries[defining_lib_name]
        value = (
            defining_lib_info.tls_offset + defining_symbol["st_value"] + rel["r_addend"]
        )
        loader.write_word(address, value)
    else:
        # Resolves to the offset of the current module's TLS block
        value = loader.read_word(address) + libinfo.tls_offset + rel["r_addend"]
        loader.write_word(address, value)
    return True


# x64 ELF loader


class X64RelocationTypes(IntEnum):
    R_X86_64_64 = 1
    R_X86_64_COPY = 5
    R_X86_64_GLOB_DAT = 6
    R_X86_64_JUMP_SLOT = 7
    R_X86_64_RELATIVE = 8
    R_X86_64_TPOFF64 = 18
    # R_X86_64_IRELATIVE = 37


class X64ELFLoader(ELFLoader):
    """An ELF loader that specializes in x86_64 ELF binaries.
    The specialization comes in the form of relocation types that are x86_64
    specific.
    """


X64ELFLoader.register_relocator(X64RelocationTypes.R_X86_64_64, direct_64)
X64ELFLoader.register_relocator(X64RelocationTypes.R_X86_64_GLOB_DAT, create_got_entry)
X64ELFLoader.register_relocator(X64RelocationTypes.R_X86_64_JUMP_SLOT, create_plt_entry)
X64ELFLoader.register_relocator(
    X64RelocationTypes.R_X86_64_RELATIVE, adjust_by_program_base
)
X64ELFLoader.register_relocator(X64RelocationTypes.R_X86_64_COPY, dynamic_copy)
X64ELFLoader.register_relocator(
    X64RelocationTypes.R_X86_64_TPOFF64, reloc_offset_in_thread_area
)

# AArch64 ELF loader


class AArch64RelocationTypes(IntEnum):
    R_AARCH64_ABS64 = 257
    R_AARCH64_GLOB_DAT = 1025
    R_AARCH64_JUMP_SLOT = 1026
    R_AARCH64_RELATIVE = 1027


class AArch64ELFLoader(ELFLoader):
    """An ELF loader that specializes in AArch64 ELF binaries.
    The specialization comes in the form of relocation types that are AArch64
    specific.
    """


AArch64ELFLoader.register_relocator(AArch64RelocationTypes.R_AARCH64_ABS64, direct_64)
AArch64ELFLoader.register_relocator(
    AArch64RelocationTypes.R_AARCH64_GLOB_DAT, create_got_entry
)
AArch64ELFLoader.register_relocator(
    AArch64RelocationTypes.R_AARCH64_JUMP_SLOT, create_plt_entry
)
AArch64ELFLoader.register_relocator(
    AArch64RelocationTypes.R_AARCH64_RELATIVE, adjust_by_program_base
)
