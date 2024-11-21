class ExtraFrameAndProcedureInformationMsSymbol:
    PDB_ID = 0x1012

    def __init__(self, pdb, reader):
        super().__init__(pdb, reader)
        self.procedure_frame_total_length = reader.parse_unsigned_int_val()
        self.procedure_frame_padding_length = reader.parse_unsigned_int_val()
        self.padding_offset = reader.parse_var_sized_offset(32)
        self.callee_save_registers_byte_count = reader.parse_unsigned_int_val()
        self.exception_handler_offset = reader.parse_var_sized_offset(32)
        self.exception_handler_section_id = reader.parse_unsigned_short_val()

    def get_pdb_id(self):
        return self.PDB_ID

    @property
    def procedure_frame_total_length(self):
        return self.procedure_frame_total_length

    @property
    def procedure_frame_padding_length(self):
        return self.procedure_frame_padding_length

    @property
    def padding_offset(self):
        return self.padding_offset

    @property
    def callee_save_registers_byte_count(self):
        return self.callee_save_registers_byte_count

    @property
    def exception_handler_offset(self):
        return self.exception_handler_offset

    @property
    def exception_handler_section_id(self):
        return self.exception_handler_section_id

    # ... many more properties ...

    def emit(self, builder):
        builder.append(f"{self.get_symbol_type_name()}:")
        builder.append(f"   Frame size = {self.procedure_frame_total_length} bytes\n")
        builder.append(f"   Pad size  = {self.procedure_frame_padding_length} bytes\n")
        # ... many more lines ...

    def get_symbol_type_name(self):
        return "FRAMEPROCSYM"

    @staticmethod
    def process_flags(flags_in):
        uses_alloca = (flags_in & 0x0001) == 0x0001
        flags_in >>= 1
        # ... many more conditions ...
