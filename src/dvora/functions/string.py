from typing import List, Type

from dvora.functions.base import Function, Probe


def memcmp(x: bytes, y: bytes) -> int:
    # Python3 does not have `cmp` anymore, so I'm using this replacement.
    # Source: https://portingguide.readthedocs.io/en/latest/comparisons.html
    return (x > y) - (x < y)


def strcmp(x: bytes, y: bytes) -> int:
    """Compare two byte-strings, but only up to the first '\0' occurrence"""
    _x, _, _ = x.partition(b"\x00")
    _y, _, _ = y.partition(b"\x00")
    return memcmp(_x, _y)


def sign(x: int) -> int:
    return -1 if x < 0 else (1 if x > 0 else 0)


class TestStrlen(Function):
    NAME = "strlen"
    PARAM_DEREFS = [1]

    STRING = b"Hello, w%srld !"

    def probe(self, string):
        string_ptr = self.alloc_string(string)
        result = self.call(string_ptr)
        return result == len(string) and self.memcmp(string_ptr, string + b"\x00")

    def probe1(self):
        return self.probe(self.STRING)

    def probe2(self):
        return self.probe(self.STRING * 4)

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrnicmp(Function):
    NAME = "strnicmp"
    PARAM_DEREFS = [1, 1, 0]

    STRING1 = b"Hello, world !"
    STRING2 = b"hEllo, workk"
    STRING3 = b"hEklo, workk"

    def probe1(self):
        string_ptr1 = self.alloc_string(self.STRING1)
        string_ptr2 = self.alloc_string(self.STRING2)

        result = self.call(string_ptr1, string_ptr2, len(b"Hello, wor"))

        return (
            result == 0
            and self.memcmp(string_ptr1, self.STRING1)
            and self.memcmp(string_ptr2, self.STRING2)
        )

    def probe2(self):
        string_ptr1 = self.alloc_string(self.STRING1)
        string_ptr3 = self.alloc_string(self.STRING3)

        result = self.call(string_ptr1, string_ptr3, len(b"Hello, wor"))

        return (
            result == 3
            and self.memcmp(string_ptr1, self.STRING1)
            and self.memcmp(string_ptr3, self.STRING2)
        )

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrncpy(Function):
    NAME = "strncpy"
    PARAM_DEREFS = [1, 1, 0]

    STRING = b"Hello, world !Hel\x00lo, world !Hello, world !Hello, world !"

    def probe1(self):
        src_ptr = self.alloc_string(self.STRING)
        dst_ptr = self.alloc_mem(len(self.STRING) + 1)

        result = self.call(dst_ptr, src_ptr, 10)

        return (
            result == dst_ptr
            and self.memcmp(src_ptr, self.STRING + b"\x00")
            and self.memcmp(dst_ptr, self.STRING[:10])
        )

    def probe2(self):
        src_ptr = self.alloc_string(self.STRING)
        dst_ptr = self.alloc_mem(len(self.STRING) + 1)

        result = self.call(dst_ptr, src_ptr, 30)

        real_size = self.STRING.find(b"\x00")

        return (
            result == dst_ptr
            and self.memcmp(src_ptr, self.STRING + b"\x00")
            and self.memcmp(dst_ptr, self.STRING[:real_size])
            and self.memcmp(dst_ptr + real_size, bytes(30 - real_size))
        )

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrcat(Function):
    NAME = "strcat"
    PARAM_DEREFS = [1, 1]

    STRING = b"Hello,"
    STRING2 = b" world !"

    def probe(self):
        ptr = self.alloc_mem(len(self.STRING) + len(self.STRING2) + 1)
        self.write_string(ptr, self.STRING)
        ptr2 = self.alloc_string(self.STRING2)

        result = self.call(ptr, ptr2)

        return (
            result == ptr
            and self.memcmp(ptr, self.STRING + self.STRING2)
            and self.memcmp(ptr2, self.STRING2)
        )

    PROBES = Probe(probe)


class TestStrncat(Function):
    NAME = "strncat"
    PARAM_DEREFS = [1, 1, 0]

    STRING1 = b"Hello,"
    STRING2 = b" world !"
    SIZE_TRUNC = 3
    TOTAL_LEN = len(STRING1) + SIZE_TRUNC
    CONCATENATED = (STRING1 + STRING2)[:TOTAL_LEN] + b"\x00"

    def probe(self):
        string1_ptr = self.alloc_mem(self.TOTAL_LEN + 1)
        self.write_string(string1_ptr, self.STRING1)
        string2_ptr = self.alloc_string(self.STRING2)

        result = self.call(string1_ptr, string2_ptr, self.SIZE_TRUNC)

        return (
            result == string1_ptr
            and self.memcmp(string1_ptr, self.CONCATENATED)
            and self.memcmp(string2_ptr, self.STRING2)
        )

    PROBES = Probe(probe)


class TestStrcmp(Function):
    NAME = "strcmp"
    PARAM_DEREFS = [1, 1]

    def probe(self, string1, string2):
        string1_ptr = self.alloc_string(string1)
        string2_ptr = self.alloc_string(string2)

        result = self.call(string1_ptr, string2_ptr)

        return (
            sign(self.signed(result)) == strcmp(string1 + b"\x00", string2 + b"\x00")
            and self.memcmp(string1_ptr, string1)
            and self.memcmp(string2_ptr, string2)
        )

    STRING1 = b"Hello,"
    STRING2 = b"Hello world !"
    STRING3 = b"hello,"

    def probe1(self):
        return self.probe(self.STRING1, self.STRING2)

    def probe2(self):
        return self.probe(self.STRING2, self.STRING1)

    def probe3(self):
        return self.probe(self.STRING1, self.STRING1)

    # Test (avoid stricmp confusion)
    def probe4(self):
        return self.probe(self.STRING1, self.STRING3)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3) & Probe(probe4)


class TestStrncmp(Function):
    NAME = "strncmp"
    PARAM_DEREFS = [1, 1, 0]

    def probe(self, string1, string2, size):
        string1_ptr = self.alloc_string(string1)
        string2_ptr = self.alloc_string(string2)

        result = self.call(string1_ptr, string2_ptr, size)

        return (
            sign(self.signed(result)) == strcmp(string1[:size], string2[:size])
            and self.memcmp(string1_ptr, string1)
            and self.memcmp(string2_ptr, string2)
        )

    STRING1 = b"Hello,"
    STRING2 = b"Hello world !"
    STRING3 = b"hello,"
    STRING4 = b"Hel"
    STRING5 = b"Hel\x001o"
    STRING6 = b"Hel\x002o"
    LEN = 6

    def probe1(self):
        return self.probe(self.STRING1, self.STRING2, self.LEN)

    def probe2(self):
        return self.probe(self.STRING1, self.STRING2, self.LEN - 1)

    def probe3(self):
        return self.probe(self.STRING1, self.STRING1, self.LEN)

    def probe4(self):
        return self.probe(self.STRING1, self.STRING3, self.LEN)

    def probe5(self):
        return self.probe(self.STRING5, self.STRING6, self.LEN)

    PROBES = (
        Probe(probe1) & Probe(probe2) & Probe(probe3) & Probe(probe4) & Probe(probe5)
    )


class TestStricmp(Function):
    NAME = "stricmp"
    PARAM_DEREFS = [1, 1]

    def probe(self, string1, string2):
        string1_ptr = self.alloc_string(string1)
        string2_ptr = self.alloc_string(string2)

        result = self.call(string1_ptr, string2_ptr)

        return (
            sign(self.signed(result))
            == strcmp(string1.lower() + b"\x00", string2.lower() + b"\x00")
            and self.memcmp(string1_ptr, string1)
            and self.memcmp(string2_ptr, string2)
        )

    STRING1 = b"Hello,"
    STRING2 = b"Hello world !"
    STRING3 = b"hello,"

    def probe1(self):
        return self.probe(self.STRING1, self.STRING2)

    def probe2(self):
        return self.probe(self.STRING2, self.STRING1)

    def probe3(self):
        return self.probe(self.STRING1, self.STRING1)

    # Test (avoid strcmp confusion)
    def probe4(self):
        return self.probe(self.STRING1, self.STRING3)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3) & Probe(probe4)


class TestStrchr(Function):
    NAME = "strchr"
    PARAM_DEREFS = [1, 0]

    STRING = b"Hello,"
    STRING2 = b"He\x00llo,"
    CHAR = b"l"

    def probe1(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr, ord(self.CHAR))

        return (result - string_ptr) == self.STRING.index(self.CHAR) and self.memcmp(
            string_ptr, self.STRING
        )

    def probe2(self):
        string2_ptr = self.alloc_string(self.STRING2)

        result = self.call(string2_ptr, ord(self.CHAR))

        return result == 0 and self.memcmp(string2_ptr, self.STRING2)

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrrchr(Function):
    NAME = "strrchr"
    PARAM_DEREFS = [1, 0]

    STRING = b"Hello, hello, "
    STRING2 = b"Hel\x00lo,"
    CHAR = b"o"

    def probe1(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr, ord(self.CHAR))

        return (result - string_ptr) == self.STRING.rindex(self.CHAR) and self.memcmp(
            string_ptr, self.STRING
        )

    def probe2(self):
        string2_ptr = self.alloc_string(self.STRING2)

        result = self.call(string2_ptr, ord(self.CHAR))

        return result == 0 and self.memcmp(string2_ptr, self.STRING2)

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrnlen(Function):
    NAME = "strnlen"
    PARAM_DEREFS = [1, 0]

    STRING = b"Hello, w%srld !"
    LEN1 = 4
    LEN2 = 20

    # TODO: There's code duplication here maybe use "min"

    def probe1(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr, self.LEN1)

        return result == self.LEN1 and self.memcmp(string_ptr, self.STRING + b"\x00")

    def probe2(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr, self.LEN2)

        return result == len(self.STRING) and self.memcmp(
            string_ptr, self.STRING + b"\x00"
        )

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrspn(Function):
    NAME = "strspn"
    PARAM_DEREFS = [1, 1]

    def probe(self, string1, string2):
        string1_ptr = self.alloc_string(string1)
        string2_ptr = self.alloc_string(string2)

        result = self.call(string1_ptr, string2_ptr)

        length = 0
        for char in string1:
            if char == b"\x00":
                break
            if char not in string2:
                break
            length += 1

        return (
            result == length
            and self.memcmp(string1_ptr, string1)
            and self.memcmp(string2_ptr, string2)
        )

    STRING1 = b"Hello,"
    STRING2 = b"leH"
    STRING3 = b"abcde"

    def probe1(self):
        return self.probe(self.STRING1, self.STRING2)

    def probe2(self):
        return self.probe(self.STRING2, self.STRING1)

    def probe3(self):
        return self.probe(self.STRING1, self.STRING3)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestStrpbrk(Function):
    NAME = "strpbrk"
    PARAM_DEREFS = [1, 1]

    def probe(self, string, charset, result_found):
        string_ptr = self.alloc_string(string)
        charset_ptr = self.alloc_string(charset)

        result = self.call(string_ptr, charset_ptr)

        length = 0
        found = False
        for char in string:
            if char == b"\x00":
                break
            if char in charset:
                found = True
                break
            length += 1

        return (
            found == result_found
            and (found and result - string_ptr == length or not found)
            and self.memcmp(string_ptr, string)
            and self.memcmp(charset_ptr, charset)
        )

    # Test
    STRING1 = b"Hello,"
    STRING2 = b"elo"
    STRING3 = b"abcd"

    def probe1(self):
        return self.probe(self.STRING1, self.STRING2, True)

    def probe2(self):
        return self.probe(self.STRING2, self.STRING1, True)

    def probe3(self):
        return self.probe(self.STRING1, self.STRING3, False)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestStrtok(Function):
    NAME = "strtok"
    PARAM_DEREFS = [1, 1]

    def __init__(self, engine, abi, heap):
        super().__init__(engine, abi, heap)
        # We have a state between probes
        self.string_ptr = 0
        self.sep_ptr = 0

    def reset(self):
        # Do not reset memory
        pass

    STRING = b"Hello, [word]!"
    SEP = b"[]"
    FIRST_TOK = 8

    def probe1(self):
        self.string_ptr = string_ptr = self.alloc_string(self.STRING)
        self.sep_ptr = sep_ptr = self.alloc_string(self.SEP)

        self.reset_mem = False

        result = self.call(string_ptr, sep_ptr)

        return result == string_ptr and self.memcmp(string_ptr, b"Hello, ")

    def probe2(self):
        result = self.call(0, self.sep_ptr)

        return result == (self.string_ptr + self.FIRST_TOK) and self.memcmp(
            self.string_ptr, b"Hello, \x00word\x00!"
        )

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrsep(Function):
    NAME = "strsep"
    PARAM_DEREFS = [2, 1]

    def __init__(self, engine, abi, heap):
        super().__init__(engine, abi, heap)
        self.string_ptr = 0
        self.delim_ptr = 0
        self.string_ptrptr = 0

    def reset(self):
        # Do not reset memory
        pass

    # Test
    STRING = b"Hello, [word]!"
    DELIM = b"[]"
    FIRST_TOK = 8

    def probe1(self):
        self.string_ptr = string_ptr = self.alloc_string(self.STRING)
        self.delim_ptr = delim_ptr = self.alloc_string(self.DELIM)
        self.string_ptrptr = string_ptrptr = self.alloc_pointer(string_ptr)

        self.reset_mem = False

        result = self.call(string_ptrptr, delim_ptr)

        ptr = self.read_pointer(string_ptrptr)

        return (
            result == string_ptr
            and ptr == (string_ptr + self.FIRST_TOK)
            and self.memcmp(string_ptr, b"Hello, ")
        )

    # TODO: Maybe drop the whole "don't reset between probes" thing and "call" twice
    def probe2(self):
        result = self.call(self.string_ptrptr, self.delim_ptr)

        # TODO: What about *(char **)string_ptr? NULL?

        return result == (self.string_ptr + self.FIRST_TOK) and self.memcmp(
            self.string_ptr, b"Hello, \x00word\x00!"
        )

    PROBES = Probe(probe1) & Probe(probe2)


class TestMemset(Function):
    NAME = "memset"
    PARAM_DEREFS = [1, 0, 0]

    STRING = b"\x11" * 0x9
    PATTERN = b"A"
    EXPECTED = PATTERN * (len(STRING) - 1) + STRING[-1].to_bytes(1, "little")

    def probe(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr, ord(self.PATTERN), len(self.STRING) - 1)

        return result == string_ptr and self.memcmp(string_ptr, self.EXPECTED)

    PROBES = Probe(probe)


class TestMemmove(Function):
    NAME = "memmove"
    PARAM_DEREFS = [1, 1, 0]

    STRING1 = b"toto\x00titi1tututata123456789"
    OFF = 5
    CPT = 8

    def probe1(self):
        string1_ptr = self.alloc_string(self.STRING1)
        string2_ptr = self.alloc_string(bytes(len(self.STRING1)))

        result = self.call(string2_ptr, string1_ptr, len(self.STRING1))

        return (
            result == string2_ptr
            and self.memcmp(string1_ptr, self.STRING1)
            and self.memcmp(string2_ptr, self.STRING1)
        )

    def probe2(self):
        string1_ptr = self.alloc_string(self.STRING1)

        result = self.call(string1_ptr + self.OFF, string1_ptr, self.CPT)

        return result == (string1_ptr + self.OFF) and self.memcmp(
            string1_ptr + self.OFF, self.STRING1[: self.CPT]
        )

    # Test 3 (avoid memcpy confusion)
    def probe3(self):
        string1_ptr = self.alloc_string(self.STRING1)

        result = self.call(string1_ptr, string1_ptr + self.OFF, self.CPT)

        return result == string1_ptr and self.memcmp(
            string1_ptr, self.STRING1[self.OFF : self.OFF + self.CPT]
        )

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestMemcpy(TestMemmove):
    NAME = "memcpy"
    PARAM_DEREFS = [1, 1, 0]

    def probe2(self):
        string1_ptr = self.alloc_string(self.STRING1)

        result = self.call(string1_ptr + self.OFF, string1_ptr, self.CPT)

        return result == (string1_ptr + self.OFF) and not self.memcmp(
            string1_ptr + self.OFF, self.STRING1[: self.CPT]
        )

    def probe3(self):
        string1_ptr = self.alloc_string(self.STRING1)

        result = self.call(string1_ptr, string1_ptr + self.OFF, self.CPT)

        return result == string1_ptr and not self.memcmp(
            string1_ptr, self.STRING1[self.OFF : self.OFF + self.CPT]
        )

    # At least one of the probe2/probe3 may fail for memcpy
    PROBES = Probe(TestMemmove.probe1) & (Probe(probe2) | Probe(probe3))


class TestStrrev(Function):
    NAME = "strrev"
    PARAM_DEREFS = [1]

    STRING = b"Hello, w%srld !"

    def probe(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr)

        return result == string_ptr and self.memcmp(
            string_ptr, self.STRING[::-1] + b"\x00"
        )

    PROBES = Probe(probe)


class TestMemcmp(Function):
    NAME = "memcmp"
    PARAM_DEREFS = [1, 1, 0]

    def probe(self, string1, string2):
        string1_ptr = self.alloc_string(string1)
        string2_ptr = self.alloc_string(string2)

        result = self.call(string1_ptr, string2_ptr, len(string1))

        return (
            sign(self.signed(result)) == memcmp(string1, string2)
            and self.memcmp(string1_ptr, string1)
            and self.memcmp(string2_ptr, string2)
        )

    STRING1 = b"He\x00l2lo"
    STRING2 = b"He\x00l1lo"

    def probe1(self):
        return self.probe(self.STRING1, self.STRING2)

    def probe2(self):
        return self.probe(self.STRING2, self.STRING1)

    def probe3(self):
        return self.probe(self.STRING1, self.STRING1)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestBzero(Function):
    NAME = "bzero"
    PARAM_DEREFS = [1, 0]

    def probe(self, string):
        string_ptr = self.alloc_string(string)
        _ = self.call(string_ptr, len(string))
        return self.memcmp(string_ptr, bytes(len(string)))

    STRING = b"Hello \x00, w%srld !, hello world"

    def probe1(self):
        return self.probe(self.STRING)

    def probe2(self):
        return self.probe(self.STRING * 50)

    PROBES = Probe(probe1) & Probe(probe2)


FUNCTIONS: List[Type[Function]] = [
    TestStrlen,
    TestStrnicmp,
    TestStrncpy,
    TestStrcat,
    TestStrncat,
    TestStrcmp,
    TestStrchr,
    TestStrrchr,
    TestStrnlen,
    TestStrspn,
    TestStrpbrk,
    TestStrtok,
    TestStrsep,
    TestMemset,
    TestMemmove,
    TestStricmp,
    TestStrrev,
    TestMemcmp,
    TestBzero,
    TestStrncmp,
    TestMemcpy,
]
