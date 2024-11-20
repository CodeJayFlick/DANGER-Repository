class DbgReadIoCommand:
    def __init__(self, manager, addr, buf, len, interface_type, bus_number, address_space):
        self.addr = addr
        self.buf = buf
        self.len = len
        self.interface_type = interface_type
        self.bus_number = bus_number
        self.address_space = address_space

    def complete(self, pending):
        range_set = set()
        range_set.add((self.addr, self.addr + self.read_len))
        return range_set

    def invoke(self):
        self.read_len = manager.get_data_spaces().read_io(
            self.interface_type,
            self.bus_number,
            self.address_space,
            self.addr,
            self.buf,
            self.len
        )


class DbgManagerImpl:
    def get_data_spaces(self):
        pass


# Example usage:

manager = DbgManagerImpl()
command = DbgReadIoCommand(manager, 0x12345678, bytearray(1024), 1024, 1, 2, 3)
command.invoke()

