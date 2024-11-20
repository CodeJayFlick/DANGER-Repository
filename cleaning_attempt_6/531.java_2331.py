class WrapIDebugDataSpaces:
    def __init__(self):
        pass

    def __init__(self, pv_instance):
        self.pv_instance = pv_instance

    def read_virtual(self, offset: int, buffer: bytes, buffer_size: int, bytes_read: int) -> int:
        return _invoke_hr(1, self.pv_instance, offset, buffer, buffer_size, bytes_read)

    def write_virtual(self, offset: int, buffer: bytes, buffer_size: int, bytes_written: int) -> int:
        return _invoke_hr(2, self.pv_instance, offset, buffer, buffer_size, bytes_written)

    def read_physical(self, offset: int, buffer: bytes, buffer_size: int, bytes_read: int) -> int:
        return _invoke_hr(3, self.pv_instance, offset, buffer, buffer_size, bytes_read)

    def write_physical(self, offset: int, buffer: bytes, buffer_size: int, bytes_written: int) -> int:
        return _invoke_hr(4, self.pv_instance, offset, buffer, buffer_size, bytes_written)

    def read_control(self, processor: int, offset: int, buffer: bytes, buffer_size: int, bytes_read: int) -> int:
        return _invoke_hr(5, self.pv_instance, processor, processor, offset, buffer, buffer_size, bytes_read)

    def write_control(self, processor: int, offset: int, buffer: bytes, buffer_size: int, bytes_written: int) -> int:
        return _invoke_hr(6, self.pv_instance, offset, buffer, buffer_size, bytes_written)

    def read_bus_data(self, bus_data_type: int, bus_number: int, slot_number: int, offset: int, buffer: bytes, buffer_size: int, bytes_read: int) -> int:
        return _invoke_hr(7, self.pv_instance, bus_data_type, bus_number, slot_number, offset, buffer, buffer_size, bytes_read)

    def write_bus_data(self, bus_data_type: int, bus_number: int, slot_number: int, offset: int, buffer: bytes, buffer_size: int, bytes_written: int) -> int:
        return _invoke_hr(8, self.pv_instance, bus_data_type, bus_number, slot_number, offset, buffer, buffer_size, bytes_written)

    def read_io(self, interface_type: int, bus_number: int, address_space: int, offset: int, buffer: bytes, buffer_size: int, bytes_read: int) -> int:
        return _invoke_hr(9, self.pv_instance, interface_type, bus_number, address_space, offset, buffer, buffer_size, bytes_read)

    def write_io(self, interface_type: int, bus_number: int, address_space: int, offset: int, buffer: bytes, buffer_size: int, bytes_written: int) -> int:
        return _invoke_hr(10, self.pv_instance, interface_type, bus_number, address_space, offset, buffer, buffer_size, bytes_written)

    def read_msr(self, msr: int, value: int) -> int:
        return _invoke_hr(11, self.pv_instance, msr, value)

    def write_msr(self, msr: int, value: int) -> int:
        return _invoke_hr(12, self.pv_instance, msr, value)

    def read_debugger_data(self, offset: int, buffer: bytes, buffer_size: int, bytes_read: int) -> int:
        return _invoke_hr(13, self.pv_instance, offset, buffer, buffer_size, bytes_read)


class ByReference:
    pass


def _invoke_hr(index: int, pv_instance: object, *args):
    # Implement the logic for invoking HR here
    pass

