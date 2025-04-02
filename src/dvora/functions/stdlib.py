from typing import List, Type

from dvora.functions.base import Function, Probe


class TestAbs(Function):
    NAME = "abs"
    PARAM_DEREFS = [0]

    VALUE = 42

    def probe1(self):
        result = self.call(self.VALUE + 1)
        return result == (self.VALUE + 1)

    def probe2(self):
        result = self.call(self.unsigned(-1 * self.VALUE))
        return result == self.VALUE

    PROBES = Probe(probe1) & Probe(probe2)


class TestA64l(Function):
    NAME = "a64l"
    PARAM_DEREFS = [1]

    STRING = b"v/"
    VALUE = 123

    def probe(self):
        string_ptr = self.alloc_string(self.STRING)
        result = self.call(string_ptr)
        return result == self.VALUE and self.memcmp(string_ptr, self.STRING)

    PROBES = Probe(probe)


class TestAtoi(Function):
    NAME = "atoi"
    PARAM_DEREFS = [1]

    STRING = b"44"
    STRING2 = b"127.0.0.1"

    def probe(self, string):
        string_ptr = self.alloc_string(string)
        result = self.call(string_ptr)
        return result == int(string.split(b".")[0]) and self.memcmp(string_ptr, string)

    def probe1(self):
        return self.probe(self.STRING)

    def probe2(self):
        return self.probe(self.STRING2)

    PROBES = Probe(probe1) & Probe(probe2)


FUNCTIONS: List[Type[Function]] = [TestAbs, TestA64l, TestAtoi]
