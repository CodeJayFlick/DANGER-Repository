class MethodRecordMs:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader') -> None:
        super().__init__(pdb, reader)
        self.attributes = ClassFieldMsAttributes(reader)
        reader.parse_bytes(2)  # structure padding
        self.procedure_record_number = RecordNumber.parse(pdb, reader, RecordCategory.TYPE, 32)

        if (self.attributes.get_property() in [ClassFieldMsAttributes.Property.INTRO,
                                                 ClassFieldMsAttributes.Property.INTRO_PURE]):
            self.optional_offset = reader.parse_unsigned_int_val()
        else:
            self.optional_offset = -1
