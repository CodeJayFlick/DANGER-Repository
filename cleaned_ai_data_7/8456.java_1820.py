class MethodRecord16Ms:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)
        self.attributes = ClassFieldMsAttributes(reader)
        self.procedure_record_number = RecordNumber.parse(pdb, reader, 16)

        if self.attributes.get_property() == ClassFieldMsAttributes.Property.INTRO:
            self.optional_offset = reader.parse_unsigned_int_val()
        else:
            self.optional_offset = -1

class AbstractPdb:
    pass

class PdbByteReader:
    def parse_unsigned_int_val(self) -> int:
        # Implement this method
        pass

class ClassFieldMsAttributes:
    class Property:
        INTRO = 0

    def __init__(self, reader: 'PdbByteReader') -> None:
        self.reader = reader

    def get_property(self) -> 'ClassFieldMsAttributes.Property':
        return self.reader.parse_unsigned_int_val()

class RecordNumber:
    @classmethod
    def parse(cls, pdb: 'AbstractPdb', reader: 'PdbByteReader', category: int, size: int) -> None:
        # Implement this method
        pass

