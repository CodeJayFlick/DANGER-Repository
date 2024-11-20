class InlinedFunctionCallsiteExtendedMsSymbol:
    PDB_ID = 0x115d

    def __init__(self):
        self.pointer_to_inliner = None
        self.pointer_to_this_block_end = None
        self.inlinee_record_number = None
        self.invocations_count = None
        self.binary_annotation_opcode_list = []

    @classmethod
    def from_pdb_reader(cls, pdb, reader):
        symbol = cls()
        super().__init__(pdb)
        symbol.pointer_to_inliner = reader.parse_unsigned_int_val()
        symbol.pointer_to_this_block_end = reader.parse_unsigned_int_val()
        symbol.inlinee_record_number = RecordNumber.from_pdb_reader(pdb, reader, 32)
        symbol.invocations_count = reader.parse_unsigned_int_val()

        while reader.has_more():
            instruction = InstructionAnnotation(reader)
            if instruction.get_instruction_code() != InstructionAnnotation.Opcode.INVALID:
                symbol.binary_annotation_opcode_list.append(instruction)

    def get_pointer_to_inliner(self):
        return self.pointer_to_inliner

    def get_pointer_to_this_block_end(self):
        return self.pointer_to_this_block_end

    def get_inlinee_record_number(self):
        return self.inlinee_record_number

    def get_invocations_count(self):
        return self.invocations_count

    def get_binary_annotation_opcode_list(self):
        return self.binary_annotation_opcode_list

    @classmethod
    def emit(cls, builder, symbol):
        builder.append(f"{symbol.get_symbol_type_name()}: Parent: {hex(symbol.pointer_to_inliner)}, End: {hex(symbol.pointer_to_this_block_end)}, PGO Edge Count: {symbol.invocations_count}, Inlinee: {symbol.pdb.getTypeRecord(symbol.inlinee_record_number)}\n")
        count = 0
        for instruction in symbol.binary_annotation_opcode_list:
            if count == 4:
                builder.append("\n")
                count = 0
            builder.append(instruction)
            count += 1

    @classmethod
    def get_symbol_type_name(cls):
        return "INLINESITE2"
