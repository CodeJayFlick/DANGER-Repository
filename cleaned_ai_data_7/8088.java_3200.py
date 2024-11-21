class AbstractProcedureStartMipsMsSymbol:
    def __init__(self, pdb, reader, internals):
        super().__init__(pdb, reader)
        self.internals = internals

    @property
    def parent_pointer(self):
        return self.internals.get_parent_pointer()

    @property
    def end_pointer(self):
        return self.internals.get_end_pointer()

    @property
    def next_pointer(self):
        return self.internals.get_next_pointer()

    @property
    def procedure_length(self):
        return self.internals.get_procedure_length()

    @property
    def debug_start_offset(self):
        return self.internals.get_debug_start_offset()

    @property
    def debug_end_offset(self):
        return self.internals.get_debug_end_offset()

    @property
    def type_record_number(self):
        return self.internals.get_type_record_number()

    @property
    def offset(self):
        return self.internals.get_offset()

    @property
    def segment(self):
        return self.internals.get_segment()

    @property
    def name(self):
        return self.internals.get_name()

    def emit(self, builder):
        builder.append(self.special_type_string())
        self.internals.emit(builder)
        builder.insert(0, self.symbol_type_name())

    @abstractmethod
    def get_special_type_string(self):
        pass

class ProcedureStartMipsMsSymbolInternals:
    def __init__(self):
        pass

    def get_parent_pointer(self):
        # implement this method
        pass

    def get_end_pointer(self):
        # implement this method
        pass

    def get_next_pointer(self):
        # implement this method
        pass

    def get_procedure_length(self):
        # implement this method
        pass

    def get_debug_start_offset(self):
        # implement this method
        pass

    def get_debug_end_offset(self):
        # implement this method
        pass

    def get_type_record_number(self):
        # implement this method
        pass

    def get_offset(self):
        # implement this method
        pass

    def get_segment(self):
        # implement this method
        pass

    def get_name(self):
        # implement this method
        pass

class AbstractPdb:
    def __init__(self, pdb_byte_reader):
        self.pdb_byte_reader = pdb_byte_reader

    @abstractmethod
    def emit(self, builder):
        pass

class PdbByteReader:
    def __init__(self):
        pass

    @abstractmethod
    def read(self):
        pass
