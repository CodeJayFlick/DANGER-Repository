Here is the translation of the Java code into equivalent Python:

```Python
class PEx64UnwindInfo:
    UNW_FLAG_NHANDLER = 0x00
    UNW_FLAG_EHANDLER = 0x01
    UNW_FLAG_UHANDLER = 0x02
    UNW_FLAG_CHAININFO = 0x04

    UNWIND_INFO_VERSION_MASK = 0x07
    UNWIND_INFO_FLAGS_MASK = 0x1F
    UNWIND_INFO_FLAGS_SHIFT = 3
    UNWIND_INFO_FRAME_REGISTER_MASK = 0x0F
    UNWIND_INFO_FRAME_OFFSET_SHIFT = 4
    UNWIND_INFO_OPCODE_MASK = 0x0F
    UNWIND_INFO_OPCODE_INFO_SHIFT = 4

    def __init__(self, start_offset):
        self.start_offset = start_offset

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    @property
    def flags(self):
        return self._flags

    @flags.setter
    def flags(self, value):
        self._flags = value

    @property
    def size_of_prolog(self):
        return self._size_of_prolog

    @size_of_prolog.setter
    def size_of_prolog(self, value):
        self._size_of_prolog = value

    @property
    def count_of_unwind_codes(self):
        return self._count_of_unwind_codes

    @count_of_unwind_codes.setter
    def count_of_unwind_codes(self, value):
        self._count_of_unwind_codes = value

    @property
    def frame_register(self):
        return self._frame_register

    @frame_register.setter
    def frame_register(self, value):
        self._frame_register = value

    @property
    def frame_offset(self):
        return self._frame_offset

    @frame_offset.setter
    def frame_offset(self, value):
        self._frame_offset = value

    def has_exception_handler(self):
        return (self.flags & PEx64UnwindInfo.UNW_FLAG_EHANDLER) == PEx64UnwindInfo.UNW_FLAG_EHANDLE