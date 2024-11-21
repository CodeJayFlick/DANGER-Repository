class ModuleInformation600:
    def __init__(self, pdb):
        if not pdb:
            raise ValueError("pdb cannot be null")
        self.pdb = pdb
        self.section_contribution = SectionContribution600()

    def parse_additionals(self, reader):
        ec_symbolic_information_enabled = (reader.read_byte() & 0x01) == 0x01
        spare >>= 1
        name_index_source_file = reader.parse_unsigned_int_val()
        name_index_compiler_pdb_path = reader.parse_unsigned_int_val()
        module_name = reader.parse_null_terminated_string(self.pdb.get_reader_options().get_one_byte_charset())
        object_file_name = reader.parse_null_terminated_string(self.pdb.get_reader_options().get_one_byte_charset())

    def dump_additionals(self):
        return f"""
nameIndexSourceFile: {self.name_index_source_file}
nameIndexCompilerPdbPath: {self.name_index_compiler_pdb_path}
"""

class SectionContribution600:
    pass

class PdbByteReader:
    def read_byte(self):
        # implement this method
        pass

    def parse_unsigned_int_val(self):
        # implement this method
        pass

    def parse_null_terminated_string(self, charset):
        # implement this method
        pass

# Example usage:

pdb = AbstractPdb()  # implement this class
reader = PdbByteReader()
module_info = ModuleInformation600(pdb)
try:
    module_info.parse_additionals(reader)
except ValueError as e:
    print(f"Error: {e}")
print(module_info.dump_additionals())
