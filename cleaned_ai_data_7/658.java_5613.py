class DbgWriteIoCommand:
    def __init__(self, manager: 'DbgManagerImpl', addr: int, buf: memoryview, len: int,
                 interface_type: int, bus_number: int, address_space: int):
        self.addr = addr
        self.interface_type = interface_type
        self.bus_number = bus_number
        self.address_space = address_space
        self.buf = buf[:len]

    def invoke(self) -> None:
        manager.get_data_spaces().write_io(
            self.interface_type, self.bus_number, self.address_space,
            self.addr, memoryview(self.buf), len(self.buf)
        )
