class AbstractUsingNamespaceMsSymbol:
    def __init__(self, pdb, reader, str_type):
        super().__init__(pdb, reader)
        self.name = reader.parse_string(pdb, str_type)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: {self.name}")

class PdbByteReader:
    def parse_string(self, pdb, str_type):
        # implement this method as needed
        pass

class AbstractPdb:
    @property
    def get_symbol_type_name(self):
        return "symbol type name"

# Example usage:

pdb = AbstractPdb()
reader = PdbByteReader()
str_type = "string type"
ms_symbol = AbstractUsingNamespaceMsSymbol(pdb, reader, str_type)

builder = StringBuilder()  # assuming a StringBuilder class exists
ms_symbol.emit(builder)
print(builder.toString())
