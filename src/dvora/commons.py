import attr


def align(address: int, alignment: int) -> int:
    if alignment <= 1:
        return address
    return address & ~(alignment - 1)


def align_up(address: int, alignment: int) -> int:
    if alignment <= 1:
        return address
    return (address + alignment - 1) & ~(alignment - 1)


@attr.s(auto_attribs=True)
class Chunk:
    address: int
    data: bytes
    protection: int
    label: str


STACK_BOTTOM: int = 0x1230000
STACK_SIZE: int = 0x10000
PAGE_SIZE: int = 0x1000
VECTORS_START: int = 0xFFFF0000

PROT_NONE: int = 0
PROT_READ: int = 1
PROT_WRITE: int = 2
PROT_EXEC: int = 4
