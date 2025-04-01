import sys

from dvora.emulation import Emulation
from dvora.machine import machine_from_elf
from dvora.abi import get_abi_class
from dvora.functions import FUNCTIONS
from dvora.heap import Heap

from loguru import logger

logger.remove()
logger.add(sys.stderr, level="ERROR")


def candidate_checkers_from_elf(elf_file):
    # note: .text is at 0x2000 by default
    emu = Emulation(elf_file, [])
    emu.trace_mode(False)
    machine = machine_from_elf(elf_file)
    abi_class = get_abi_class(machine)
    abi = abi_class(emu.engine, machine)
    heap = Heap(emu.engine.vm, abi)
    emu.engine.take_snapshot()
    return [function(emu.engine, abi, heap) for function in FUNCTIONS]


def divinate_function(candidate_checkers, address):
    guesses = []
    for checker in candidate_checkers:
        try:
            if checker.execute(address):
                guesses.append(checker.NAME)
        except Exception as e:
            print(e)
    print(f"{hex(address)}: {' / '.join(guesses) if guesses else 'no match'}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            f"Usage: {sys.argv[0]} <elf file> <function 1 address_in_hex> <function 2 address_in_hex> ..."
        )
        exit(1)
    checkers = candidate_checkers_from_elf(sys.argv[1])
    for address in sys.argv[2:]:
        divinate_function(checkers, int(address, 16))
