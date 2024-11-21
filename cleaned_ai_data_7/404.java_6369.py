class DebugExceptionRecord64:
    def __init__(self, code: int, flags: int, record: int, address: int, information: list):
        self.code = code
        self.flags = flags
        self.record = record
        self.address = address
        self.information = tuple(information)

# Example usage:
information_list = [1, 2, 3]
exception_record = DebugExceptionRecord64(0x1234, 0x5678, 0x90123456, 0x78901234, information_list)
