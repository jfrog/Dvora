import functools

from dvora.engine import VirtualMemory


class ParameterType:
    value: int
    vm: VirtualMemory

    def __init__(self, value: int, vm: VirtualMemory):
        self.value = value
        self.vm = vm


class Literal(ParameterType):
    def __repr__(self):
        return repr(self.value)


class Pointer(ParameterType):
    def read_string(self, max_length=128, offset=0):
        ptr = self.value + offset
        if self.vm.is_mapped(ptr, max_length):
            return self.vm.get_mem(ptr, max_length).split(b"\0")[0]
        return None

    def read_buffer(self, length, offset=0):
        ptr = self.value + offset
        if self.vm.is_mapped(ptr, length):
            return self.vm.get_mem(ptr, length)
        return None

    def write_buffer(self, data, offset=0):
        ptr = self.value + offset
        if self.vm.is_mapped(ptr, len(data)):
            self.vm.set_mem(ptr, data)
        # TODO: Do we need to fail silently?

    def __setitem__(self, index, value):
        if isinstance(value, (bytes, bytearray)):
            self.write_buffer(bytes(value[0]), offset=index)
        elif isinstance(value, str):
            self.write_buffer(bytes(value[0], encoding="utf8"), offset=index)
        else:
            raise ValueError("Operation not supported on {value}")

    def __repr__(self):
        return hex(self.value)


class Hook:
    def __init__(self, *param_types):
        self.param_types = param_types

    def __call__(self, func):
        @functools.wraps(func)
        def wrapped(*args, **kws):
            return func(*args, **kws)

        wrapped.param_types = self.param_types
        return wrapped


def bind_hook(abi, hook_func):
    @functools.wraps(hook_func)
    def bound(address, engine, cpu, vm):
        # pylint: disable=unused-argument
        retaddr = abi.get_ret()
        args = abi.extract_parameters(len(hook_func.param_types))
        smart_args = [ptype(arg, vm) for ptype, arg in zip(hook_func.param_types, args)]
        retval = hook_func(*smart_args)
        abi.ret(retaddr, retval)
        return True

    return bound
