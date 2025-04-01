import binascii
import socket
import struct
from typing import List, Type

from dvora.functions.base import Function, Probe


class TestNtohs(Function):
    NAME = "ntohs"
    PARAM_DEREFS = [0]

    STRING = b"hello"

    def probe1(self):
        return self.call(0x3412) == 0x1234

    def probe2(self):
        return self.call(0) == 0

    def probe3(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr)

        expected_result = (string_ptr << 8) | (string_ptr >> 8)
        expected_result &= 0xFFFF

        return result == expected_result and self.memcmp(string_ptr, self.STRING)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestNtohl(Function):
    NAME = "ntohl"
    PARAM_DEREFS = [0]

    STRING = b"hello"

    def probe1(self):
        return self.call(0x78563412) == 0x12345678

    def probe2(self):
        return self.call(0x3412) == 0x12340000

    def probe3(self):
        return self.call(0) == 0

    def probe4(self):
        string_ptr = self.alloc_string(self.STRING)

        result = self.call(string_ptr)

        return result == socket.ntohl(string_ptr) and self.memcmp(
            string_ptr, self.STRING
        )

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3) & Probe(probe4)


class TestNtohsBuffer(Function):
    NAME = "ntohs_buffer"
    PARAM_DEREFS = [1]

    def probe(self, buf):
        buf_ptr = self.alloc_mem(2)
        self.write_mem(buf_ptr, buf)

        result = self.call(buf_ptr)

        (expected,) = struct.unpack(">H", buf)

        return result == expected

    def probe1(self):
        return self.probe(b"\x12\x34")

    def probe2(self):
        return self.probe(b"\x00\x00")

    PROBES = Probe(probe1) & Probe(probe2)


class TestNtohlBuffer(Function):
    NAME = "ntohl_buffer"
    PARAM_DEREFS = [1]

    def probe(self, buf):
        buf_ptr = self.alloc_mem(4)
        self.write_mem(buf_ptr, buf)

        result = self.call(buf_ptr)

        (expected,) = struct.unpack(">I", buf)

        return result == expected

    def probe1(self):
        return self.probe(b"\x12\x34\x56\x78")

    def probe2(self):
        return self.probe(b"\x12\x34\x00\x00")

    def probe3(self):
        return self.probe(b"\x00\x00\x00\x00")

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestParseHexShort(Function):
    """
    Assuming parse_hex_short() works like self.parse_hex_short()
    """

    NAME = "parse_hex_short"
    PARAM_DEREFS = [1]

    @staticmethod
    def parse_hex_short(hexstr):
        return struct.unpack(">H", binascii.unhexlify(hexstr))[0]

    def probe(self, hexstr):
        hexstr_ptr = self.alloc_string(hexstr)

        result = self.call(hexstr_ptr)

        expected = self.parse_hex_short(hexstr)

        return result == expected and self.memcmp(hexstr_ptr, hexstr)

    STRING1 = b"1234"
    STRING2 = b"0000"
    STRING3 = b"ffff"

    def probe1(self):
        return self.probe(self.STRING1)

    def probe2(self):
        return self.probe(self.STRING2)

    def probe3(self):
        return self.probe(self.STRING3)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestHex2BytesIn(Function):
    """
    Assuming hex2bytes() works like self.hex2bytes()
    And that hex2bytes signature is:
    `hex2bytes(char *hexbytes, char *output, size_t output_size)`
    (we do not check the return value)
    """

    NAME = "hex2bytes_in"
    PARAM_DEREFS = [1, 1, 0]

    @staticmethod
    def hex2bytes(s):
        return binascii.unhexlify(s)

    def probe(self, hexstr):
        hexstr_ptr = self.alloc_string(hexstr)
        out_ptr = self.alloc_string(bytes(len(hexstr)))

        _ = self.call(hexstr_ptr, out_ptr, len(hexstr))

        expected = self.hex2bytes(hexstr)

        return self.memcmp(hexstr_ptr, hexstr) and self.memcmp(out_ptr, expected)

    STRING1 = b"123456789A"
    STRING2 = b"deadbeef"
    STRING3 = b"001200"

    def probe1(self):
        return self.probe(self.STRING1)

    def probe2(self):
        return self.probe(self.STRING2)

    def probe3(self):
        return self.probe(self.STRING3)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestHex2BytesInOut(Function):
    """
    Assuming hex2bytes() works like self.hex2bytes()
    And that hex2bytes signature is:
    `hex2bytes(char *hexbytes, char *output, size_t *inout_size)`
    (we do not check the return value)
    """

    NAME = "hex2bytes_inout"
    PARAM_DEREFS = [1, 1, 1]

    @staticmethod
    def hex2bytes(s):
        return binascii.unhexlify(s)

    def probe(self, hexstr):
        hexstr_ptr = self.alloc_string(hexstr)
        out_ptr = self.alloc_string(bytes(len(hexstr)))
        inout_buflen_ptr = self.alloc_pointer(len(hexstr))

        _ = self.call(hexstr_ptr, out_ptr, inout_buflen_ptr)

        expected = self.hex2bytes(hexstr)

        return (
            self.memcmp(hexstr_ptr, hexstr)
            and self.memcmp(out_ptr, expected)
            and self.read_pointer(inout_buflen_ptr) == len(hexstr) // 2
        )

    STRING1 = b"123456789A"
    STRING2 = b"deadbeef"
    STRING3 = b"001200"

    def probe1(self):
        return self.probe(self.STRING1)

    def probe2(self):
        return self.probe(self.STRING2)

    def probe3(self):
        return self.probe(self.STRING3)

    PROBES = Probe(probe1) & Probe(probe2) & Probe(probe3)


class TestStrtoul(Function):
    NAME = "strtoul"
    PARAM_DEREFS = [1, 2, 0]

    STRING1 = b"44"
    STRING2 = b"127.0.0.1"

    def probe(self, string):
        string_ptr = self.alloc_string(string)

        result = self.call(string_ptr)

        return result == int(string.split(b".")[0]) and self.memcmp(string_ptr, string)

    def probe1(self):
        return self.probe(self.STRING1)

    def probe2(self):
        return self.probe(self.STRING2)

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrstr(Function):
    NAME = "strstr"
    PARAM_DEREFS = [1, 1]

    # Test
    HAYSTACK1 = b"Hello World,"
    HAYSTACK2 = b"He\x00llo World,"
    NEEDLE = b"llo"

    def probe1(self):
        haystack_ptr = self.alloc_string(self.HAYSTACK1)
        needle_ptr = self.alloc_string(self.NEEDLE)

        result = self.call(haystack_ptr, needle_ptr)

        return (
            (result - haystack_ptr) == self.HAYSTACK1.index(self.NEEDLE)
            and self.memcmp(haystack_ptr, self.HAYSTACK1)
            and self.memcmp(needle_ptr, self.NEEDLE)
        )

    def probe2(self):
        haystack_ptr = self.alloc_string(self.HAYSTACK2)
        needle_ptr = self.alloc_string(self.NEEDLE)

        result = self.call(haystack_ptr, needle_ptr)

        return (
            result == 0
            and self.memcmp(haystack_ptr, self.HAYSTACK2)
            and self.memcmp(needle_ptr, self.NEEDLE)
        )

    PROBES = Probe(probe1) & Probe(probe2)


class TestStrcpyCustom(Function):
    NAME = "strcpy"
    PARAM_DEREFS = [1, 1]

    # Test 1 - long string for avoiding fixed-size small string copies
    STRING1 = (
        b"This is a long string so we won't get confused with small fixed-size copies"
    )

    def probe1(self):
        string_ptr = self.alloc_string(self.STRING1)
        dst_ptr = self.alloc_mem(len(self.STRING1) + 1)

        result = self.call(dst_ptr, string_ptr)

        return (
            result == dst_ptr
            and self.memcmp(string_ptr, self.STRING1)
            and self.memcmp(dst_ptr, self.STRING1)
        )

    # Test 2 - short truncated string to avoid large buffer copies
    STRING2 = b"Short trunc\0ated"

    def probe2(self):
        string_ptr = self.alloc_string(self.STRING2)
        dst_ptr = self.alloc_mem(len(self.STRING2) + 1)

        result = self.call(dst_ptr, string_ptr)

        str2_null = self.STRING2.index(b"\0")
        str2_head = self.STRING2[: str2_null + 1]
        str2_tail = self.STRING2[str2_null + 1 :]

        return (
            result == dst_ptr
            and self.memcmp(string_ptr, self.STRING2)
            and self.memcmp(dst_ptr, str2_head)
            and not self.memcmp(dst_ptr + len(str2_head), str2_tail)
        )

    PROBES = Probe(probe1) & Probe(probe2)


FUNCTIONS: List[Type[Function]] = [
    TestNtohs,
    TestNtohl,
    TestNtohsBuffer,
    TestNtohlBuffer,
    TestParseHexShort,
    TestStrtoul,
    TestStrcpyCustom,
    TestStrstr,
    TestHex2BytesIn,
    TestHex2BytesInOut,
]
