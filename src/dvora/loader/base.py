"""Implementation of loaders - mechanisms that take a binary (or a bunch of
them) and load them into the memory of the emulated process.

The loader needs to parse the binaries, copy their contents to the emulated
memory space, perform the modification described by the binaries (various
relocations etc...) and finally maintain some bookkeeping to be (possible) used
during emulation.
"""

from typing import IO

import attr

from dvora.engine import VirtualMemory


@attr.s(auto_attribs=True)
class LoadCommand:
    """Represent all the information needed to map a part of a binary into
    memory.
    """

    #: The relative VM address of the map's start
    start: int
    #: The last VM address of the map
    end: int
    #: Protection (R/W/X)
    flags: int
    #: Offset in the backing file from which to map.
    file_page_start: int
    #: Alignment requirements for the map.
    alignment: int

    def load(self, stream: IO, vm: VirtualMemory, load_address: int):
        """Perform the load command: Load from ``stream`` (which represents
        the file) into ``vm`` which represents the virtual memory, at the
        specified ``load_address``.
        """
        vm.mmap(
            addr=self.start + load_address,
            size=self.end - self.start,
            prot=self.flags,
            fp=stream,
            offset=self.file_page_start,
            alignment=self.alignment,
        )
