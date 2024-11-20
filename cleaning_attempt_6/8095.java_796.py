class AbstractRegisterMsSymbol:
    def __init__(self, pdb, reader, record_number_size):
        self.record_number = None  # Initialize with None for now.
        self.register_name = None  # Same here.
        self.name = None  # And same again.

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}: ")
        self.emit_register_information(builder)
        builder.append(f", Type: {pdb.get_record_by_number(self.record_number)}")
        builder.append(f", {self.name}")

    @abstractmethod
    def parse_register(self, reader) -> 'RegisterName':
        pass

    @abstractmethod
    def emit_register_information(self, builder):
        pass


class RegisterName:
    # You might need to add some methods here depending on how you plan to use this class.
    pass


# I assume these are classes from the PDB library. If not, please provide more information about them.
class AbstractPdb:
    def get_record_by_number(self, record_number):
        pass

class RecordNumber:
    @classmethod
    def parse(cls, pdb, reader, category_type, size):
        # You might need to add some logic here depending on how you plan to use this class.
        pass


# I assume these are classes from the PDB library. If not, please provide more information about them.
class StringParseType:
    pass

class PdbByteReader:
    def parse_string(self, pdb, str_type):
        # You might need to add some logic here depending on how you plan to use this class.
        pass

    def align4(self):
        # You might need to add some logic here depending on how you plan to use this class.
        pass
