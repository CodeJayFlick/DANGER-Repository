Here is the translation of the Java code into Python:

```Python
class MemoryBlockDiff:
    NAME = 0x001
    START_ADDRESS = 0x002
    END_ADDRESS = 0x004
    SIZE = 0x008
    READ = 0x010
    WRITE = 0x020
    EXECUTE = 0x040
    VOLATILE = 0x080
    TYPE = 0x100
    INIT = 0x200
    SOURCE = 0x400
    COMMENT = 0x800
    ALL = 0xFFF

    def __init__(self, block1: 'MemoryBlock', block2: 'MemoryBlock'):
        self.block1 = block1
        self.block2 = block2
        self.diff_flags = self.get_diff_flags()

    @property
    def block1(self):
        return self._block1

    @block1.setter
    def block1(self, value):
        self._block1 = value

    @property
    def block2(self):
        return self._block2

    @block2.setter
    def block2(self, value):
        self._block2 = value

    def is_name_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.NAME) != 0

    def is_start_address_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.START_ADDRESS) != 0

    def is_end_address_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.END_ADDRESS) != 0

    def is_size_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.SIZE) != 0

    def is_read_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.READ) != 0

    def is_write_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.WRITE) != 0

    def is_execute_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.EXECUTE) != 0

    def is_volatile_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.VOLATILE) != 0

    def is_type_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.TYPE) != 0

    def is_init_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.INIT) != 0

    def is_source_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.SOURCE) != 0

    def is_comment_different(self) -> bool:
        return (self.diff_flags & MemoryBlockDiff.COMMENT) != 0

    def get_differences_as_string(self) -> str:
        buf = StringBuffer()
        if self.diff_flags & MemoryBlockDiff.NAME:
            buf.append("Name ")
        if self.diff_flags & MemoryBlockDiff.START_ADDRESS:
            buf.append("StartAddress ")
        if self.diff_flags & MemoryBlockDiff.END_ADDRESS:
            buf.append("EndAddress ")
        if self.diff_flags & MemoryBlockDiff.SIZE:
            buf.append("Size ")
        if self.diff_flags & MemoryBlockDiff.READ:
            buf.append("R ")
        if self.diff_flags & MemoryBlockDiff.WRITE:
            buf.append("W ")
        if self.diff_flags & MemoryBlockDiff.EXECUTE:
            buf.append("X ")
        if self.diff_flags & MemoryBlockDiff.VOLATILE:
            buf.append("Volatile ")
        if self.diff_flags & MemoryBlockDiff.TYPE:
            buf.append("Type ")
        if self.diff_flags & MemoryBlockDiff.INIT:
            buf.append("Initialized ")
        if self.diff_flags & MemoryBlockDiff.SOURCE:
            buf.append("Source ")
        if self.diff_flags & MemoryBlockDict.COMMENT:
            buf.append("Comment ")
        return buf.toString()

    def get_diff_flags(self) -> int:
        if not self.block1 or not self.block2:
            return 0
        flags = 0
        if self.block1.name != self.block2.name:
            flags |= MemoryBlockDiff.NAME
        if self.block1.start_address != self.block2.start_address:
            flags |= MemoryBlockDiff.START_ADDRESS
        if self.block1.end_address != self.block2.end_address:
            flags |= MemoryBlockDiff.END_ADDRESS
        if self.block1.size != self.block2.size:
            flags |= MemoryBlockDiff.SIZE
        if self.block1.is_read() != self.block2.is_read():
            flags |= MemoryBlockDiff.READ
        if self.block1.is_write() != self.block2.is_write():
            flags |= MemoryBlockDiff.WRITE
        if self.block1.is_execute() != self.block2.is_execute():
            flags |= MemoryBlockDiff.EXECUTE
        if self.block1.is_volatile() != self.block2.is_volatile():
            flags |= MemoryBlockDiff.VOLATILE
        if self.block1.type != self.block2.type:
            flags |= MemoryBlockDiff.TYPE
        if not SystemUtilities.is_equal(self.block1.source_name, self.block2.source_name):
            flags |= MemoryBlockDiff.SOURCE
        if not SystemUtilities.is_equal(self.block1.comment, self.block2.comment):
            flags |= MemoryBlockDict.COMMENT
        return flags

class MemoryBlock:
    def __init__(self, name: str, start_address: int, end_address: int, size: int, is_read: bool, is_write: bool, is_execute: bool, is_volatile: bool, type: str):
        self.name = name
        self.start_address = start_address
        self.end_address = end_address
        self.size = size
        self.is_read = is_read
        self.is_write = is_write
        self.is_execute = is_execute
        self.is_volatile = is_volatile
        self.type = type

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def start_address(self):
        return self._start_address

    @start_address.setter
    def start_address(self, value):
        self._start_address = value

    @property
    def end_address(self):
        return self._end_address

    @end_address.setter
    def end_address(self, value):
        self._end_address = value

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    @property
    def is_read(self):
        return self._is_read

    @is_read.setter
    def is_read(self, value):
        self._is_read = value

    @property
    def is_write(self):
        return self._is_write

    @is_write.setter
    def is_write(self, value):
        self._is_write = value

    @property
    def is_execute(self):
        return self._is_execute

    @is_execute.setter
    def is_execute(self, value):
        self._is_execute = value

    @property
    def is_volatile(self):
        return self._is_volatile

    @is_volatile.setter
    def is_volatile(self, value):
        self._is_volatile = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value