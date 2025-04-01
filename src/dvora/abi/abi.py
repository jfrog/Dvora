from abc import ABC, abstractmethod
from typing import ClassVar, List, Optional

from dvora.engine.engine import Engine
from dvora.machine import Machine


class ABI(ABC):
    """Encapsulates the machanics of functional ABI.

    This includes how parameters are passed, how values are returned and how
    functions track where and how to return.

    The ABI object will be linked to an instance of an
    :class:``~dvora.engine.engine.Engine`` and all operations will be reflected
    in it.
    """

    arch: ClassVar[List[str]]  #: Associated architectures
    regs_mapping: ClassVar[List[str]]  #: Registers used to pass parameters
    ret_reg_name: ClassVar[str]  #: Register used for storing the return value

    machine: Machine
    engine: Engine

    def __init__(self, engine: Engine, machine: Machine):
        self.engine = engine
        self.machine = machine

    def read_word(self, address: int) -> int:
        """Read a word from memory.

        Args:
            address: The address to read from.

        Returns:
            The decoded word stored in that address.

        """
        return self.machine.unpack_word(
            self.engine.vm.get_mem(address, self.machine.sizeof_word)
        )

    def vm_push(self, element: int):
        self.engine.push_word(element)

    @abstractmethod
    def set_ret(self, ret_addr: int):
        pass

    @abstractmethod
    def get_ret(self) -> int:
        pass

    def setup_parameters(self, parameters: List[int]):
        for position, param in enumerate(parameters):
            if position < len(self.regs_mapping):
                # Regs argument
                setattr(self.engine.cpu, self.regs_mapping[position], param)
            else:
                # Stack argument
                self.vm_push(param)

    def extract_parameters(self, nparams: int) -> List[int]:
        params = []
        for position in range(nparams):
            if position < len(self.regs_mapping):
                params.append(getattr(self.engine.cpu, self.regs_mapping[position]))
            else:
                stack_offset = (
                    position - len(self.regs_mapping)
                ) * self.machine.sizeof_word
                params.append(
                    self.engine.peek_stack(
                        position + stack_offset, self.machine.sizeof_word
                    )
                )
        return params

    @abstractmethod
    def ret(self, retaddr: int, retval: Optional[int] = None):
        """
        Perpare the CPU to "return" to the specified address with an optional
        return value.
        """

    def get_result(self) -> int:
        return int(getattr(self.engine.cpu, self.ret_reg_name))

    def prepare_function_call(
        self, address: int, args: List[int], end_addr: int
    ) -> None:
        # pylint: disable=unused-argument
        self.setup_parameters(args)
        self.set_ret(end_addr)

    @abstractmethod
    def dump_regs(self):
        pass

    @abstractmethod
    def dump_stacktrace(self):
        pass
