class DbgReadBusDataCommand:
    def __init__(self, manager, addr, buf, len, bus_data_type, bus_number, slot_number):
        self.addr = addr
        self.buf = buf
        self.len = len
        self.bus_data_type = bus_data_type
        self.bus_number = bus_number
        self.slot_number = slot_number

    def complete(self, pending=None) -> set:
        return {range(self.addr, self.addr + self.read_len)}

    def invoke(self):
        read_len = manager.get_data_spaces().read_bus_data(
            self.bus_data_type,
            self.bus_number,
            self.slot_number,
            self.addr,
            self.buf,
            self.len
        )
