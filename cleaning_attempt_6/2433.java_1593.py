class DBTraceProgramViewMemoryBlock:
    def __init__(self, program: 'DBTraceProgramView', region: 'DBTraceMemoryRegion'):
        self.program = program
        self.region = region
        self.info = [DBTraceProgramViewMemoryBlockSourceInfo(self)]

    class DBTraceProgramViewMemoryBlockSourceInfo:
        def get_length(self):
            return self.region.get_length()

        def get_min_address(self):
            return self.region.get_min_address()

        def get_max_address(self):
            return self.region.get_max_address()

        def get_description(self):
            return f"Trace region: {self.region}"

        def get_file_bytes(self):
            return None

        def get_file_bytes_offset(self, address=None):
            return -1

        def get_mapped_range(self):
            return None

        def get_byte_mapping_scheme(self):
            return None

        def get_memory_block(self):
            return self

        def contains(self, address: 'Address'):
            return self.region.get_range().contains(address)

        def __str__(self):
            return self.get_description()

    @property
    def start(self) -> 'Address':
        return self.region.get_min_address()

    @property
    def end(self) -> 'Address':
        return self.region.get_max_address()

    @property
    def size(self) -> int:
        return self.region.get_length()

    @property
    def name(self):
        return self.region.name

    @name.setter
    def name(self, value: str):
        if not isinstance(value, str):
            raise TypeError("Name must be a string")
        try:
            self.region.set_name(value)
        except LockException as e:
            print(f"Error setting the name of {self}: {e}")

    @property
    def comment(self) -> str:
        return None

    @comment.setter
    def comment(self, value: str):
        pass  # TODO Auto-generated method stub

    @property
    def is_read(self) -> bool:
        return self.region.is_read()

    @is_read.setter
    def is_read(self, r: bool):
        try:
            self.region.set_read(r)
        except LockException as e:
            print(f"Error setting the read permission of {self}: {e}")

    @property
    def is_write(self) -> bool:
        return self.region.is_write()

    @is_write.setter
    def is_write(self, w: bool):
        try:
            self.region.set_write(w)
        except LockException as e:
            print(f"Error setting the write permission of {self}: {e}")

    @property
    def is_execute(self) -> bool:
        return self.region.is_execute()

    @is_execute.setter
    def is_execute(self, e: bool):
        try:
            self.region.set_execute(e)
        except LockException as e:
            print(f"Error setting the execute permission of {self}: {e}")

    @property
    def volatile_(self) -> bool:
        return self.region.is_volatile()

    @volatile_.setter
    def volatile_(self, v: bool):
        try:
            self.region.set_volatile(v)
        except LockException as e:
            print(f"Error setting the volatility of {self}: {e}")

    @property
    def source_name(self) -> str:
        return "Trace"

    @source_name.setter
    def source_name(self, value: str):
        raise NotImplementedError("Setting the source name is not supported")

    def get_byte(self, addr: 'Address') -> int:
        if self.region.get_range().contains(addr):
            space = self.program.trace.memory_manager.get_memory_space(
                self.region.get_address_space(), False
            )
            if space is None:
                raise MemoryAccessException("Space does not exist")
            buf = bytearray(1)
            bytes_read = space.view_bytes(self.program.snap, addr, buf)
            return buf[0]
        else:
            raise MemoryAccessException()

    def get_bytes(self, addr: 'Address', b: bytearray) -> int:
        if self.region.get_range().contains(addr):
            return self.get_bytes(addr, b, 0, len(b))
        else:
            raise MemoryAccessException()

    def get_bytes(self, addr: 'Address', b: bytearray, off: int, len: int) -> int:
        space = self.program.trace.memory_manager.get_memory_space(
            self.region.get_address_space(), False
        )
        if space is None:
            raise MemoryAccessException("Space does not exist")
        return space.view_bytes(self.program.snap, addr, bytes(b[off: off + len]))

    def put_byte(self, addr: 'Address', b: int) -> int:
        if self.put_bytes(addr, bytearray([b])) == 1:
            return 1
        else:
            raise MemoryAccessException()

    def put_bytes(self, addr: 'Address', b: bytearray) -> int:
        return self.put_bytes(addr, b, 0, len(b))

    def put_bytes(self, addr: 'Address', b: bytearray, off: int, len: int) -> int:
        space = self.program.trace.memory_manager.get_memory_space(
            self.region.get_address_space(), True
        )
        if space is None:
            raise MemoryAccessException("Space does not exist")
        return space.put_bytes(self.program.snap, addr, bytes(b[off: off + len]))

    @property
    def type(self) -> 'MemoryBlockType':
        return MemoryBlockType.DEFAULT

    @property
    def initialized(self) -> bool:
        return True

    @property
    def mapped(self) -> bool:
        return False

    @property
    def overlay(self) -> bool:
        return False

    @property
    def loaded(self) -> bool:
        return True

    def get_source_infos(self):
        return self.info


class MemoryBlockType:
    DEFAULT = 0
