class DvoraException(Exception):
    """Base exception for Dvora"""


class UnimplementedArchitecture(DvoraException):
    """The specified architecture is not (yet) supported."""


class NotEnoughMemory(DvoraException):
    """Indicates that a memory allocation request failed due to insufficient
    memory.
    """


class InvalidMemoryAccess(DvoraException):
    """Indicates the emulated code attempted to access unmapped memory."""


class InvalidFetch(InvalidMemoryAccess):
    pass


class StackOverflow(InvalidMemoryAccess):
    """A special case of :class:`~dvora.exceptions.InvalidMemoryAccess` which
    is triggered with the faulted memory is in the page just above the stack.
    """


class CorruptedFrame(DvoraException):
    """Indicates that a corrupted frame was reached while unwinding the
    stack-frames.
    """


class LoaderError(DvoraException):
    """Indicates a binary loading error."""


class HeapError(DvoraException):
    """Base class for heap related exceptions."""


class HeapUnaccountedFreeError(HeapError):
    """Indicates an attempt to free memory that has not been allocated."""


class HeapDoubleFreeError(HeapError):
    """Indicates an attempt to free memory that has already been freed."""


class ProbeTimeout(DvoraException):
    """Indicates a timeout has expired while probing a function."""


class LoaderNotImplemented(DvoraException):
    """Indicates there is no loader for the specified machine."""
