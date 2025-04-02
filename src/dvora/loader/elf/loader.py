"""Implementation of ELF loaders.
"""

import os
import re
from collections import defaultdict
from contextlib import suppress
from operator import attrgetter
from typing import (
    Callable,
    ClassVar,
    Dict,
    Iterator,
    List,
    Optional,
    Tuple,
    cast,
)

import attr
from elftools.common.utils import struct_parse
from elftools.elf.constants import P_FLAGS
from elftools.elf.dynamic import Dynamic, DynamicSegment, DynamicTag
from elftools.elf.elffile import ELFError, ELFFile
from elftools.elf.relocation import RelocationTable
from elftools.elf.sections import Symbol
from loguru import logger

from dvora.commons import PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE, Chunk
from dvora.engine import VirtualMemory
from dvora.exceptions import LoaderError
from dvora.hooking import Hook, Literal
from dvora.loader.elf.clustering import (
    Cluster,
    ClusterSet,
    is_loadable_section,
)
from dvora.machine import Machine


def get_flags(p_flags: int) -> int:
    """Convert ELF memory protections flags to Dvora's protection flags"""
    flags = 0
    if p_flags & P_FLAGS.PF_R:
        flags |= PROT_READ
    if p_flags & P_FLAGS.PF_W:
        flags |= PROT_WRITE
    if p_flags & P_FLAGS.PF_X:
        flags |= PROT_EXEC
    return flags


@attr.s(auto_attribs=True)
class LibraryInfo:
    """Encapsulates all the properties of a loaded library instance together
    with some convenience methods.
    """

    #: Name of the library (encoded it its SONAME entry)
    soname: str
    #: Where the first segment of the library is loaded
    start: int
    #: End address of the library's last segment
    end: int
    #: A reference to the library's ``Dynamic`` object
    dynamic: Dynamic
    #: Offset of this library's TLS in the thread area (-1 if there's no TLS)
    tls_offset: int = -1
    #: Index of the library in the DTV (-1 if there's no TLS)
    lib_id: int = -1
    #: The vaddr of the first load command (sometimes the binary is built to
    #: be based of some non-zero address for convenience)
    load_bias: int = 0

    def iter_symbols(self) -> Iterator[Symbol]:
        """Iterate over all the symbols in the library"""
        if self.dynamic:
            yield from self.dynamic.iter_symbols()

    def iter_symbol_range(self, start: int, stop: int) -> Iterator[Symbol]:
        """Iterate over symbols in a specfied symbol index range."""
        for index in range(start, stop):
            yield self.get_symbol(index)

    def get_symbol(self, index: int) -> Symbol:
        """Retrieve the ``Symbol`` object associated with a specific ``index``.

        Args:
            index: The index of the symbol in the library's symbol table.

        Returns:
            A ``Symbol`` object.

        """
        dynamic = self.dynamic

        _, tab_offset = dynamic.get_table_offset("DT_SYMTAB")
        if not tab_offset:
            raise LoaderError("Library does not contain DT_SYMTAB")

        symbol_size = dynamic.elfstructs.Elf_Sym.sizeof()

        # We're accessing private members as a necessity until we can get this
        # implementation of `get_symbol` into pyelftools
        string_table = dynamic._get_stringtable()  # pylint: disable=protected-access

        symbol = struct_parse(
            dynamic.elfstructs.Elf_Sym,
            dynamic._stream,  # pylint: disable=protected-access
            index * symbol_size + tab_offset,
        )

        symbol_name = string_table.get_string(symbol["st_name"])

        return Symbol(symbol, symbol_name)

    def get_relocation_tables(self) -> Dict[str, RelocationTable]:
        """Get all the relocation tables in the library

        Returns:
            A dictionary from the type of the relocation table to a
            ``RelocationTable`` object.

        """
        if self.dynamic:
            return cast(
                Dict[str, RelocationTable], self.dynamic.get_relocation_tables()
            )
        return {}


class ThreadArea:
    """The thread-area is where the TLS (Thread Local Storage) of all the
    modules is stored.

    The contents of the thread area are extended on each new library that's
    being loaded.
    """

    #: The (chunked) contents of the thread area. We need the chunk to be
    #: mutable (hence ``bytearray``)
    chunks: List[bytearray]
    #: A map from a library-id to the index of the chunk it represents
    tls: Dict[int, int]
    #: Total size of the thread area (basically the size of all the chunks + two
    #: reserved words)
    size: int
    #: Size of the header of the thread area.
    header_size: int

    def __init__(self, machine: Machine):
        self.chunks = []
        self.header_size = (
            machine.sizeof_word * 2
        )  # One word for the DTV pointer, and one reserved
        self.size = self.header_size
        self.tls = {}

    def add(self, lib_id: int, chunk: bytearray, alignment: int) -> int:
        """Add a TLS area for a specified library.

        Args:
            lib_id: The id of the library for which the TLS is added.
            chunk: TLS initial contents.
            alignment: The boundary on which the start of the TLS should be
                aligned.

        Returns:
            The offset of the TLS from the beginning of the thread area.

        """
        aligned = (self.size + alignment - 1) & (-alignment)
        padding = bytearray(aligned - self.size)
        self.chunks.append(padding)
        self.chunks.append(chunk)
        self.tls[lib_id] = len(self.chunks) - 1
        self.size += len(padding) + len(chunk)
        return aligned

    def set_tdata(self, lib_id: int, tdata: bytes):
        """Write the thread local data (".tdata" section) into the corresponding chunk.

        Since the thread local data may contain relocations, its content are not
        known at the time of ``ThreadArea.add``. This method allows setting data
        by the module's ID.

        Args:
            lib_id: The index of the library.
            tdata: The ``bytes`` representing the (already relocated) thread local data.

        """
        chunk_idx = self.tls[lib_id]
        self.chunks[chunk_idx][: len(tdata)] = tdata

    def encode(self) -> bytes:
        """Finalize the contents of the thread area.

        The structure of the thread area is as follows: First word is the pointer
        to the DTV, second word is reserved (to pthread), and then follow all the
        TLS areas with padding before them to meet their alignment requirements.

        Returns:
            A ``bytes`` object representing the contents of the thread area

        """
        return bytes(self.header_size) + b"".join(self.chunks)


def find_segment(elf: ELFFile, p_type: str):
    for segment in elf.iter_segments():
        if segment["p_type"] == p_type:
            return segment
    return None


def dynamic_segment(elf: ELFFile):
    return find_segment(elf, "PT_DYNAMIC")


def safe_iter_dynamic(dynamic: DynamicSegment) -> Iterator[DynamicTag]:
    try:
        yield from dynamic.iter_tags()
    except ELFError:
        logger.exception(
            f"Exception while processing PT_DYNAMIC on {dynamic.stream.name}"
        )
        return


class Stubs:
    """Manages unresolved symbols.

    During relocation, we might run into a relocation entry that requires a
    symbol that has not been loaded (could happen if not all the needed
    libraries are found in the supplied ``LD_LIBRARY_PATH``).

    Normally, a runtime loader will terminate with a "Unresolved linker error",
    what we do instead is keep track of all the relocation addresses that need
    the address of an unresolved symbol, and then, once the library has been
    loaded (and all unresolved symbols have been accounted for), we provide
    an address for all the symbols in a special "stubs" area.

    Since each symbol has a unique address in the stubs area, it's possible
    to hook unresolved symbols.
    """

    #: A mapping of unresolved symbols to their relocation addreses - will be
    #: used to generate stubs
    relocation_debts: Dict[str, List[int]]
    #: A mapping of unresolved symbols to their stub address
    symbols: Dict[str, int]

    def __init__(self):
        self.relocation_debts = defaultdict(list)
        self.symbols = {}

    def add_relocation_debt(self, name: str, address: int):
        """Record a relocation address and the name of the symbol it requires."""
        self.relocation_debts[name].append(address)

    def repay_relocation_debts(
        self, vm: VirtualMemory, machine: Machine
    ) -> Iterator[Tuple[int, int]]:
        """Record a relocation address and the name of the symbol it requires."""
        # We now need to repay the relocation debt of unresolved symbols
        # First, we need to calculate the size of the stubs area. We need
        # one word for each symbol
        if not self.relocation_debts:
            return

        n_stubs = len(self.relocation_debts)
        stubs_area_size = n_stubs * machine.sizeof_word
        # Allocate memory for the stubs
        stubs_area_ptr = vm.allocate_padded(stubs_area_size)
        # For each unresolved symbol, "allocate" an address for the stub in
        # the stub area
        for i, name in enumerate(self.relocation_debts):
            stub_address = stubs_area_ptr + i * machine.sizeof_word
            self.symbols[name] = stub_address
            # Patch all the "skipped" relocation entries to the stub's
            # address
            for reloc_address in self.relocation_debts[name]:
                yield reloc_address, stub_address

    @property
    def stubs_range(self) -> Tuple[int, int]:
        if self.symbols:
            stub_addresses = self.symbols.values()
            start = min(stub_addresses)
            end = max(stub_addresses)
            return start, end
        return 1, 0


class ELFLoader:
    """An implementation of a loader for ELF files into an emulated virtual
    memory space.

    This is a complete ecosystem that includes:

        * Recursive loading of needed libraries
        * Symbol resolution
        * TLS mechanics
    """

    # pylint: disable=too-many-instance-attributes
    #: The interface to the virtual memory into which the libraries are loaded.
    vm: VirtualMemory
    #: The architecture for which the libraries are meant.
    machine: Machine
    #: A mapping from library name to a ``LibraryInfo`` object.
    libraries: Dict[str, LibraryInfo]
    #: A mapping from library id to ``LibraryInfo`` object.
    lib_id_map: Dict[int, LibraryInfo]
    #: Paths in which to search for libraries.
    ld_library_paths: List[str]
    #: A symbol cache. Maps from symbol name to a ``Symbol`` object and the
    #: address at which the containing library is loaded.
    symbols: Dict[str, Tuple[int, Symbol]]
    #: A map from symbol name to a ``Symbol`` object and the name of the library
    #: that exports it.
    tls_symbols: Dict[str, Tuple[str, Symbol]]
    #: A list of load-commands for all loaded libraries. Used to generate a
    #: memory snapshot.
    segments: Dict[str, List[Cluster]]
    #: Tracks the number of libraries loaded so far. This is used to generate
    #: library ids.
    library_count: int
    #: The thread area object for this loading instance. Used to piece together
    #: the contents of the thread area from the TLS segments of all the loaded
    #: libraries.
    thread_area: ThreadArea
    #: The address of the running thread area.
    thread_area_ptr: int
    #: The size of the running thread area.
    thread_area_size: int
    #: The address of the DTV (Dynamic Thread Vector). This is a runtime index
    #: from library id to its TLS.
    dtv_size: int
    #: The size of the DTV.
    dtv_ptr: int
    #: Unresolved import stubs accounting
    stubs: Stubs

    #: A dictionary that maps a relocation type to a method that performs it
    RELOCATORS: ClassVar[Dict[str, Dict[int, Callable]]] = defaultdict(dict)

    def __init__(
        self,
        vm: VirtualMemory,
        machine: Machine,
        ld_library_paths: Optional[List[str]] = None,
    ):
        self.vm = vm
        self.libraries = {}
        self.lib_id_map = {}
        self.ld_library_paths = ld_library_paths or []
        self.symbols = {}
        self.tls_symbols = {}
        self.machine = machine
        self.segments = defaultdict(list)
        self.library_count = 0
        self.thread_area = ThreadArea(machine)
        self.stubs = Stubs()

    @classmethod
    def register_relocator(cls, r_type: int, relocator: Callable):
        cls.RELOCATORS[cls.__name__][r_type] = relocator

    @classmethod
    def get_relocator(cls, r_type: int) -> Optional[Callable]:
        return cls.RELOCATORS[cls.__name__].get(r_type, None)

    def take_snapshot(self) -> Iterator[Chunk]:
        """Take a snapshot of the state of all loaded libraries and dump it
        as (address, buffer) tuples.

        Yields:
            ``Chunk``\\ s represeting segments of memory
        """
        for soname in self.segments:
            clusters = self.segments[soname]
            base = min(map(attrgetter("page_start"), clusters), default=0)
            for cluster in clusters:
                start = cluster.page_start
                size = cluster.page_end - cluster.page_start
                data = self.vm.get_mem(start, size)
                offset = start - base
                yield Chunk(
                    address=start,
                    data=data,
                    protection=get_flags(cluster.protection),
                    label=f"{soname}+{offset:#x}",
                )

        start, end = self.stubs.stubs_range
        if start < end:
            data = self.vm.get_mem(start, end - start)
            yield Chunk(
                address=start,
                data=data,
                protection=PROT_READ | PROT_EXEC,
                label="stubs",
            )

    def read_word(self, address: int) -> int:
        raw = self.vm.get_mem(address, self.machine.sizeof_word)
        return self.machine.unpack_word(raw)

    def write_word(self, address: int, word: int):
        raw = self.machine.pack_word(word)
        self.vm.set_mem(address, raw)

    @staticmethod
    def iter_needed(elf: ELFFile) -> Iterator[str]:
        dynamic = dynamic_segment(elf)
        if dynamic:
            for entry in safe_iter_dynamic(dynamic):
                if entry["d_tag"] == "DT_NEEDED":
                    yield entry.needed

    @staticmethod
    def get_soname(filename: str) -> str:
        with open(filename, "rb") as stream:
            elf = ELFFile(stream)
            dynamic = dynamic_segment(elf)
            if not dynamic:
                return os.path.basename(filename)
            for entry in safe_iter_dynamic(dynamic):
                if entry["d_tag"] == "DT_SONAME":
                    return cast(str, entry.soname)
            return os.path.basename(filename)

    @staticmethod
    def get_arch(filename: str) -> str:
        with open(filename, "rb") as stream:
            elf = ELFFile(stream)
            return cast(str, elf.header["e_machine"])

    def format_address(self, address: int) -> str:
        """Format an address into a human-readable form.


        This makes it more convenient to debug.

        Args:
            address: An (absolute) address.

        Returns:
            The address formatted into "library-name::offset-in-hex".
            If the address does not belong to a library, then this is just the
            hexadecimal representation of the address.

        """
        for libinfo in self.libraries.values():
            if libinfo.start <= address < libinfo.end:
                return f"{libinfo.soname}::{hex(address - libinfo.start)}"
        return hex(address)

    def find_library(self, library_name: str) -> Optional[str]:
        """Find the path of the library with a specified name.
        This will scan the ``ld_library_path`` for the first file whose "SONAME"
        matches the query.
        Args:
            library_name: Name of the library to find.

        Returns:
            Path to the library.

        """
        for path in self.ld_library_paths:
            for candidate_library in os.listdir(path):
                candidate_library_path = os.path.join(path, candidate_library)
                with suppress(ELFError):
                    # We want to ignore any file in the path that's not an ELF
                    soname = self.get_soname(candidate_library_path)
                    if soname == library_name:
                        return candidate_library_path
        return None

    def _map_library(
        self, soname: str, elf: ELFFile, load_address: Optional[int] = None
    ) -> Tuple[int, int, int]:
        """
        Map a library into memory.

        Args:
            soname: The name of the library to map.
            elf: The object representing the library.
            load_address: An optional address at which to load the library.
                If no load address is specified, the first vacant address
                large enough to house the library will be used.

        Returns:
            The load-address, load-size and load-bias.

        """
        cluster_set: ClusterSet = ClusterSet.from_elf(elf)

        min_vaddr = min(map(attrgetter("page_start"), cluster_set))
        max_vaddr = max(map(attrgetter("page_end"), cluster_set))

        load_size = max_vaddr - min_vaddr

        if load_address is None:
            # We want to find a memory location that would allow page-sized
            # padding on both sides (so that an inter-library overflow would
            # cause a page-fault)
            # load_address = self.vm.allocate_padded(load_size)
            load_address = self.vm.find_vacant_memory(load_size + 2 * PAGE_SIZE)
            if load_address is None:
                raise LoaderError(f"No vacant memory of size 0x{load_size:x}")
            load_address += PAGE_SIZE
        elif not self.vm.is_vacant(load_address, load_size):
            raise LoaderError(f"Cannot map at {hex(load_address)}")

        load_offset = load_address - cluster_set.page_start
        for cluster in cluster_set:
            # Map the memory the cluster occupies
            cluster.start += load_offset
            cluster.end += load_offset
            self.vm.add_memory_page(
                cluster.page_start,
                get_flags(cluster.protection),
                bytes(cluster.page_size),
            )
            # Load each segment in the cluster to its address in the mapped
            # memory
            for fragment in cluster:
                if fragment.size > 0:
                    # Only read from segments that have a "presence" in the
                    # binary
                    self.vm.set_mem(fragment.address + load_offset, fragment.data)

            self.segments[soname].append(cluster)

        return load_address, load_size, min_vaddr

    def resolve_symbols(self, libinfo: LibraryInfo):
        """Work the symbols from the specified library into the global symbol
        cache.

        This process is aware of symbol binding strength, and the class of the
        symbol.
        """
        for symbol in libinfo.iter_symbols():
            st_info = symbol["st_info"]
            if symbol["st_shndx"] != "SHN_UNDEF":
                # This is a defined symbol
                # Try to see if it's already bound
                bound = self.symbols.get(symbol.name, None)
                if bound:
                    _, current = bound
                    # If the current bound symbol is STB_WEAK, we might
                    # re-bind it
                    if current["st_info"]["bind"] == "STB_WEAK":
                        # We will only re-bind if the new symbol is not weak
                        if st_info["bind"] == "STB_GLOBAL":
                            self.symbols[symbol.name] = (
                                libinfo.start - libinfo.load_bias,
                                symbol,
                            )
                elif st_info["bind"] in {"STB_GLOBAL", "STB_WEAK"}:
                    # Not bound yet, bind the symbol name to the current
                    # instance of the symbol
                    if st_info["type"] == "STT_TLS":
                        self.tls_symbols[symbol.name] = (libinfo.soname, symbol)
                    else:
                        self.symbols[symbol.name] = (
                            libinfo.start - libinfo.load_bias,
                            symbol,
                        )

    def fix_single_relocation(self, rel, address: int, libinfo: LibraryInfo) -> bool:
        """Fix a single relocation entry. Returns a boolean success status.

        Current failure mode is "relocation entry references a (yet) unbound
        symbol".
        """
        relocator = self.get_relocator(rel["r_info_type"])
        if relocator:
            # There's a custom relocator for this relocation type, use it
            return cast(bool, relocator(self, address, rel, libinfo))

        if rel["r_info_sym"]:
            name = libinfo.get_symbol(rel["r_info_sym"]).name
            bound = self.symbols.get(name)
            if bound:
                base, symbol = bound
                value = base + symbol["st_value"]
                self.write_word(address, value)
            else:
                return False
        else:
            # Relocate the memory address based on the relocation
            # type.
            # We'll start by just adding the load address
            contents = self.read_word(address)
            value = contents + libinfo.start
            self.write_word(address, value)
        return True

    def fix_relocations(self, libinfo: LibraryInfo):
        """Fix the relocation entries for the specified library."""
        for _, rel_table in libinfo.get_relocation_tables().items():
            for rel in rel_table.iter_relocations():
                address = rel["r_offset"] + libinfo.start - libinfo.load_bias
                if not self.fix_single_relocation(rel, address, libinfo):
                    sym = libinfo.get_symbol(rel["r_info_sym"])
                    # Record the "skipped" relocation entry for later
                    self.stubs.add_relocation_debt(sym.name, address)

    def load_static_elf(self, soname: str, elf: ELFFile):
        self.libraries[soname] = LibraryInfo(soname, 0, 0, None, -1, 0)
        segment_clusters = ClusterSet.from_elf(elf)

        if not segment_clusters.clusters:
            self.load_elf_from_sections(soname, elf)
        else:
            for cluster in segment_clusters:
                start_page, end_page = cluster.page_bounds
                self.vm.add_memory_page(
                    start_page,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    bytes(end_page - start_page),
                )
                logger.info(f"mapped cluster {hex(start_page)}..{hex(end_page)}")
                for fragment in cluster:
                    if fragment.size > 0:
                        self.vm.set_mem(fragment.address, fragment.data)
                self.segments[soname].append(cluster)

    def load_elf_from_sections(self, soname: str, elf: ELFFile):
        """
        Just load full sections into emulation memory
        (needed for over-simplified ELF files without segments)
        """
        for cluster in ClusterSet.from_elf_sections(elf.iter_sections()):
            logger.info(
                f"Mapping cluster {cluster.page_start:#x}..{cluster.page_end:#x}"
            )
            self.vm.add_memory_page(
                cluster.page_start, cluster.protection, bytes(cluster.page_size)
            )
            self.segments[soname].append(cluster)
            for fragment in cluster:
                logger.info(
                    f"Writing {len(fragment.data)} bytes to {fragment.address:#x}"
                )
                self.vm.set_mem(fragment.address, fragment.data)

    def elf_machine_before_rtld_reloc(self, libinfo: LibraryInfo):
        pass

    def _load_internal(self, filename: str, load_address: Optional[int] = None) -> int:
        soname = self.get_soname(filename)
        if soname in self.libraries:
            return self.libraries[soname].start

        with open(filename, "rb") as stream:
            elf = ELFFile(stream)

            if is_elfify_elf(elf):
                # If we are dealing with an ELF produced by elfify, we load it
                # by sections only
                self.load_elf_from_sections(soname, elf)
                return 0

            if not elf.get_section_by_name(".dynsym"):
                # This is not a dynamic ELF, so we need to load it exactly at
                # the addresses it specifies
                self.load_static_elf(soname, elf)
                # A "static" ELF's base address is 0
                return 0

            lib_id = self.library_count
            # 1. Map the current library into memory
            loaded_at, load_size, load_bias = self._map_library(
                soname, elf, load_address
            )
            tls_segment = find_segment(elf, "PT_TLS")
            if tls_segment:
                # We start off with a blank TLS. If there's any ".tdata" in the
                # library, we need to defer copying it to the TLS until after
                # we've completed relocation on the library
                tls_offset = self.thread_area.add(
                    lib_id, bytearray(tls_segment["p_memsz"]), tls_segment["p_align"]
                )
            else:
                tls_offset = -1

            # Register the library
            dynamic = dynamic_segment(elf)
            self.libraries[soname] = libinfo = LibraryInfo(
                soname, loaded_at, loaded_at + load_size, dynamic, tls_offset, lib_id
            )
            libinfo.load_bias = load_bias

            self.lib_id_map[lib_id] = libinfo
            self.library_count += 1
            logger.info(f"{soname} loaded at {hex(loaded_at)}")
            # 2. Load needed libraries
            for needed_lib in self.iter_needed(elf):
                needed_lib_path = self.find_library(needed_lib)
                if needed_lib_path:
                    if elf.header["e_machine"] != self.get_arch(needed_lib_path):
                        continue
                    self._load_internal(needed_lib_path)

            # 3. Resolve symbols
            self.resolve_symbols(libinfo)

            self.elf_machine_before_rtld_reloc(libinfo)
            # 4. Fix relocations
            self.fix_relocations(libinfo)

            # 5. Copy the (now relocated) ".tdata" section to the TLS
            if tls_segment:
                tdata = self.vm.get_mem(
                    tls_segment["p_vaddr"] + loaded_at, tls_segment["p_filesz"]
                )

                self.thread_area.set_tdata(libinfo.lib_id, tdata)

        return self.libraries[soname].start

    def load(self, filename: str, load_address: Optional[int] = None) -> int:
        """Load an ELF file with all dependencies and allocate/fill the required
        TLS structures.

        Args:
            filename: The path of the ELF to load.
            load_address: An optional load address for the file.

        Returns:
            The address at which the ELF file was loaded.

        """
        load_address = self._load_internal(filename, load_address)
        self.dtv_size = (self.machine.sizeof_word) * (self.library_count + 1)
        self.dtv_ptr = self.vm.allocate_padded(self.dtv_size)

        thread_area_bytes = self.thread_area.encode()
        self.thread_area_size = len(thread_area_bytes)
        self.thread_area_ptr = self.vm.allocate_padded(self.thread_area_size)

        self.vm.set_mem(self.thread_area_ptr, thread_area_bytes)
        self.write_word(self.thread_area_ptr, self.dtv_ptr)

        self.write_word(self.dtv_ptr, self.library_count)
        dtv = self.dtv_ptr + self.machine.sizeof_word
        for lib_id in range(self.library_count):
            libinfo = self.lib_id_map[lib_id]
            self.write_word(dtv, self.thread_area_ptr + libinfo.tls_offset)
            dtv += self.machine.sizeof_word

        # Relocate all the places skipped due to unresolved symbols
        for reloc_address, stub_address in self.stubs.repay_relocation_debts(
            self.vm, self.machine
        ):
            self.write_word(reloc_address, stub_address)

        return load_address

    def dlsym(self, name: str) -> Optional[int]:
        """Resolve the address to which a symbol is bound"""
        bound = self.symbols.get(name, None)
        if not bound:
            # If the symbol is not bound, then it has a stub implementation
            return self.stubs.symbols.get(name, None)
        base, symbol = bound
        return base + cast(int, symbol["st_value"])

    @Hook(Literal)
    def tls_get_addr(self, desc: Literal):
        ptr = desc.value
        sizeof_word = self.machine.sizeof_word
        module_index = self.read_word(ptr)
        offset = self.read_word(ptr + sizeof_word)
        tls_ptr = self.read_word(self.dtv_ptr + (module_index + 1) * sizeof_word)
        return tls_ptr + offset


ELFIFY_SECTION_NAME_RE = re.compile(r"\.s\d+")


def is_elfify_elf(elf: ELFFile) -> bool:
    """
    Is this ELF a product of ELFify, and therefore be loaded by segments?

    To identify such files, we check whether all of the (loadable) sections
    conform to the name pattern ".s<number>" (e.g. ".s0", ".s1", ...).
    """
    for section in filter(is_loadable_section, elf.iter_sections()):
        if not ELFIFY_SECTION_NAME_RE.match(section.name):
            return False
    return True


def load_from_clusters(clusters: ClusterSet, vm: VirtualMemory, load_address: int):
    bias = load_address - clusters.start
    for cluster in clusters:
        vm.add_memory_page(
            cluster.page_start + bias,
            cluster.protection,
            bytes(cluster.page_size),
        )
        for fragment in cluster:
            vm.set_mem(fragment.address + bias, fragment.data)


def load_elf(filename: str, vm: VirtualMemory, load_address: int = 0):
    """Load a single ELF file into memory without resolving dependencies.
    This exists purely as backward compatibility for function-discovery mode.

    In the future this will be replaced with the ``ELFLoader`` class.

    Args:
        filename: Path to the ELF file to load.
        vm: The memory into which to load.
        load_address: Where in the memory the ELF should load.
    """
    with open(filename, "rb") as stream:
        elf = ELFFile(stream)
        if is_elfify_elf(elf):
            clusters = ClusterSet.from_elf_sections(elf.iter_sections())
        else:
            clusters = ClusterSet.from_elf_segments(elf.iter_segments())
        load_from_clusters(clusters, vm, load_address)
