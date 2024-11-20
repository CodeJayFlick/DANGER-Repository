class ModuleTypeReferenceMsSymbol:
    PDB_ID = 0x115f

    def __init__(self):
        self.does_not_reference_any_type = False
        self.references_z7_pch_types = False
        self.contains_z7_pch_types = False
        self.contains_z7_type_information = False
        self.contains_zi_or_zi_type_information = False
        self.contains_other_module_type_references = False

    def process_flags(self, flags):
        self.does_not_reference_any_type = (flags & 0x01) == 1
        flags >>= 1
        self.references_z7_pch_types = (flags & 0x01) == 1
        flags >>= 1
        self.contains_z7_pch_types = (flags & 0x01) == 1
        flags >>= 1
        self.contains_z7_type_information = (flags & 0x01) == 1
        flags >>= 1
        self.contains_zi_or_zi_type_information = (flags & 0x01) == 1
        flags >>= 1
        self.contains_other_module_type_references = (flags & 0x01) == 1

    def __str__(self):
        if not self.does_not_reference_any_type:
            return f"MODTYPEREF: {'' if not self.contains_z7_type_information else f'/Z7 TypeRef, StreamNumber={type_reference_stream_number:x}'}{'' if not self.references_z7_pch_types or not self.contains_z7_pch_types else ', own PCH types' if not self.module_containing_referenced_pch_types else f', reference PCH types in Module {module_containing_referenced_pch_types:x}'}{'' if not self.contains_other_module_type_references and not self.contains_zi_or_zi_type_information else f', shared with Module {module_sharing_referenced_types:x}'}{'' if not self.contains_zi_or_zi_type_information else ', StreamNumber={type_reference_stream_number:x} (type), StreamNumber={type_id_stream_number:x} (ID)'}"
        return "No TypeRef"

    def get_pdb_id(self):
        return PDB_ID

class AbstractPdb:
    pass

class PdbByteReader:
    def parse_unsigned_int_val(self):
        raise NotImplementedError()

    def parse_unsigned_short_val(self):
        raise NotImplementedError()

    def align4(self):
        raise NotImplementedError()
