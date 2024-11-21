class AbstractDimensionedArrayConstBoundsLowerUpperMsType:
    def __init__(self):
        self.rank = None
        self.type_record_number = None
        self.lower_bound = []
        self.upper_bound = []

    def parse_beginning_fields(self, reader):
        # This method is abstract in Java and needs to be implemented by the subclass.
        pass

class PdbByteReader:
    def __init__(self, data):
        self.data = data
        self.index = 0

    def parse_bytes_remaining(self):
        return self.data[self.index:]

    def parse_unsigned_byte_val(self):
        val = int.from_bytes(self.data[self.index:self.index+1], 'big')
        self.index += 1
        return val

    def parse_short(self):
        val = int.from_bytes(self.data[self.index:self.index+2], 'big')
        self.index += 2
        return val

    def parse_int(self):
        val = int.from_bytes(self.data[self.index:self.index+4], 'big')
        self.index += 4
        return val

    def parse_long(self):
        val = int.from_bytes(self.data[self.index:self.index+8], 'big')
        self.index += 8
        return val


class PdbException(Exception):
    pass


def emit(builder, bind, pdb, type_record_number, lower_bound, upper_bound):
    pdb.get_type_record(type_record_number).emit(builder, Bind.NONE)
    for i in range(len(lower_bound)):
        builder.append("[")
        builder.append(str(lower_bound[i]))
        builder.append(":")
        builder.append(str(upper_bound[i]))
        builder.append("]")
