from functools import reduce
from operator import attrgetter, or_
from typing import Iterable, Iterator, List, Tuple, cast

import attr
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from elftools.elf.segments import Segment

from dvora.commons import (
    PAGE_SIZE,
    PROT_EXEC,
    PROT_NONE,
    PROT_READ,
    PROT_WRITE,
    align,
    align_up,
)


def is_loadable_section(section: Section) -> bool:
    # A sections is loadable if it has the ALLOC flag, and it's not empty
    return bool(section["sh_flags"] & SH_FLAGS.SHF_ALLOC) and section["sh_size"] > 0


def is_loadable_segment(segment: Segment) -> bool:
    # A segment is loadable if it's type is LOAD, and it's not empty (memory
    # size > 0)
    return bool(segment["p_type"] == "PT_LOAD") and segment["p_memsz"] > 0


@attr.s(auto_attribs=True)
class MemoryFragment:
    address: int
    size: int
    protection: int
    data: bytes


# XXX: PyLint does not deal really well with `auto_attribs=True`, so I'm
# forced to specify each attribute explicitly
@attr.s
class Cluster:
    """
    A cluster is a set of segments that overlap up to a page boundary.
    For example: (0x1000, 0x1234) and (0x1567, 0x2000) are considered to be
    overlapping because they share the same page (0x1000, 0x2000).
    """

    #: The lowest address of the cluster
    start: int = attr.ib()
    #: The highest address of the cluster
    end: int = attr.ib()
    #: A list of segments that belong to the cluster
    fragments: List[MemoryFragment] = attr.ib()

    @property
    def size(self) -> int:
        return self.end - self.start

    def __iter__(self) -> Iterator[MemoryFragment]:
        yield from self.fragments

    @staticmethod
    def from_segment(segment: Segment) -> "Cluster":
        start = segment["p_vaddr"]
        end = start + segment["p_memsz"]
        region = MemoryFragment(start, end - start, segment["p_flags"], segment.data())
        return Cluster(start, end, [region])

    @staticmethod
    def from_section(section: Section) -> "Cluster":
        start = section["sh_addr"]
        end = start + section["sh_size"]
        flags = PROT_READ
        if section["sh_flags"] & SH_FLAGS.SHF_WRITE:
            flags |= PROT_WRITE
        if section["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
            flags |= PROT_EXEC
        region = MemoryFragment(start, end - start, flags, section.data())
        return Cluster(start, end, [region])

    @property
    def page_start(self) -> int:
        return align(self.start, PAGE_SIZE)

    @property
    def page_end(self) -> int:
        return align_up(self.end, PAGE_SIZE)

    @property
    def bounds(self) -> Tuple[int, int]:
        return self.start, self.end

    @property
    def page_bounds(self) -> Tuple[int, int]:
        return self.page_start, self.page_end

    @property
    def page_size(self) -> int:
        return self.page_end - self.page_start

    def overlaps(self, other: "Cluster") -> bool:
        A, B = self.bounds
        C, D = other.bounds

        a, b = self.page_bounds
        c, d = other.page_bounds

        # If the clusters boundaries are page aligned and are tangent, they
        # are not, in fact, overlapping. This is somewhat of an optimization,
        # but it required to keep size and running time manageable.
        if B == b and C == c and b == c:
            return False

        if D == d and A == a and d == a:
            return False

        return (c <= b <= d) or (c <= a <= d) or (a <= c <= b) or (a <= d <= b)

    def merge(self, other: "Cluster"):
        """
        Merge another cluster with this one.
        The clusters are assumed to overlap.
        """
        self.start = min(self.start, other.start)
        self.end = max(self.end, other.end)
        self.fragments += other.fragments

    @property
    def protection(self) -> int:
        """The sum of protections of all contained fragments"""
        return reduce(or_, map(attrgetter("protection"), self.fragments), PROT_NONE)


class ClusterSet:
    #: A list of non-overlapping clusters
    clusters: List[Cluster]

    def __init__(self):
        self.clusters = []

    def __iter__(self) -> Iterator[Cluster]:
        yield from self.clusters

    def insert(self, new: Cluster):
        foreign = []

        for cluster in self.clusters:
            if cluster.overlaps(new):
                new.merge(cluster)
            else:
                foreign.append(cluster)

        foreign.append(new)

        self.clusters = foreign

    @property
    def page_start(self) -> int:
        return cast(int, min(map(attrgetter("page_start"), self)))

    @staticmethod
    def from_elf(elf: ELFFile) -> "ClusterSet":
        cluster_set = ClusterSet()

        for segment in filter(is_loadable_segment, elf.iter_segments()):
            cluster_set.insert(Cluster.from_segment(segment))

        return cluster_set

    @staticmethod
    def from_elf_segments(segments: Iterable[Segment]) -> "ClusterSet":
        cluster_set = ClusterSet()

        for segment in filter(is_loadable_segment, segments):
            cluster_set.insert(Cluster.from_segment(segment))

        return cluster_set

    @staticmethod
    def from_elf_sections(sections: Iterable[Section]) -> "ClusterSet":
        cluster_set = ClusterSet()

        for section in filter(is_loadable_section, sections):
            cluster_set.insert(Cluster.from_section(section))

        return cluster_set

    @property
    def start(self) -> int:
        """Address of the lowest cluster"""
        return min(map(attrgetter("start"), self.clusters), default=0)
