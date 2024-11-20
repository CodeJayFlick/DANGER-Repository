class AbstractLocalOrParameterRelativeToVirtualFramePointerMsSymbol:
    def __init__(self, pdb, reader):
        self.offset = reader.read_long()
        self.type_record_number = RecordNumber.parse(pdb, reader)
        self.attributes = LocalVariableAttributes(pdb, reader)
        self.name = reader.read_string()

class PdbByteReader:
    def read_long(self):
        # implement this method
        pass

    def parse_string(self, pdb, str_type):
        # implement this method
        pass

class RecordNumber:
    @staticmethod
    def parse(pdb, reader, category, size):
        # implement this method
        pass

class LocalVariableAttributes:
    def __init__(self, pdb, reader):
        self.attributes = reader.read_attributes()

    def emit(self, builder):
        # implement this method
        pass

def emit(symbol, builder):
    my_builder = StringBuilder()
    my_builder.append(str(symbol.type_record_number))
    symbol.attributes.emit(my_builder)
    builder.append(f"{symbol.get_symbol_type_name()}: [{symbol.offset:08X}], {my_builder} {symbol.name}")

class StringBuilder:
    def __init__(self):
        self.builder = ""

    def append(self, text):
        self.builder += str(text)

    def toString(self):
        return self.builder
