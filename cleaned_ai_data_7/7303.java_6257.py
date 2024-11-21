class MultiProgramMemoryByteProvider:
    def __init__(self, *programs):
        self.programs = programs
        self.base_addresses = [program.get_address_space().get_base_address() for program in programs]

    def get_file(self):
        if len(self.programs) != 0:
            return self.programs[1].get_executable_path()
        else:
            return None

    def get_name(self):
        if len(self.programs) != 0:
            return self.programs[1].get_name()
        else:
            return None

    def get_absolute_path(self):
        if len(self.programs) != 0:
            return self.programs[1].get_executable_path()
        else:
            return None

    def length(self):
        total_length = 0
        for program in self.programs:
            total_length += program.get_memory().size()
        return total_length

    def is_valid_index(self, index):
        for i in range(len(self.programs)):
            try:
                address = self.base_addresses[i].add(index)
                if self.programs[i].get_memory().contains(address):
                    return True
            except Exception as e:
                pass
        return False

    def close(self):
        self.programs = None
        self.base_addresses = None

    def read_byte(self, index):
        for i in range(len(self.programs)):
            try:
                return self.programs[i].get_memory().read_byte(self.base_addresses[i].add(index))
            except Exception as e:
                pass
        raise IOError("Unable to read byte at index: " + str(index))

    def read_bytes(self, index, length):
        for i in range(len(self.programs)):
            try:
                bytes = bytearray(length)
                n_read = self.programs[i].get_memory().read_bytes(self.base_addresses[i].add(index), bytes)
                if n_read != length:
                    raise IOError("Unable to read " + str(length) + " bytes at index: " + str(index))
                return bytes
            except Exception as e:
                pass
        raise IOError("Unable to read " + str(length) + " bytes at index: " + str(index))

    def get_input_stream(self, index):
        # This method is not implemented in the original Java code.
        raise NotImplementedError()
