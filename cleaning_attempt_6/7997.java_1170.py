class LinkerUnwindInfo:
    def __init__(self):
        self.version = 0
        self.flags = 0
        self.data_length = 0

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
    def data_length(self):
        return self._data_length

    @data_length.setter
    def data_length(self, value):
        self._data_length = value

    def deserialize(self, reader):
        try:
            self.version = reader.parse_unsigned_short()
            self.flags = reader.parse_unsigned_short()
            self.data_length = reader.parse_unsigned_int()
        except Exception as e:
            raise PdbException("Error parsing LinkerUnwindInfo") from e

    def __str__(self):
        return str(self.dump())

    def dump(self):
        output = "LinkerUnwindInfo--------------------------------------------\n"
        self._dump_internal(output)
        output += "End LinkerUnwindInfo----------------------------------------\n"
        return output

    def _dump_internal(self, builder):
        builder.append(f"version: 0x{self.version:04X}\n")
        builder.append(f"flags: 0x{self.flags:04X}\n")
        builder.append(f"dataLength: 0x{self.data_length:08X}\n")

class PdbByteReader:
    def parse_unsigned_short(self):
        # implement this method
        pass

    def parse_unsigned_int(self):
        # implement this method
        pass

class PdbException(Exception):
    pass
