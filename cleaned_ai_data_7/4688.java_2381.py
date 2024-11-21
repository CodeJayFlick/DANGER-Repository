class DWARFDataTypeConflictHandler:
    def __init__(self):
        pass  # do not create instances of this class

    @staticmethod
    def is_size_compatible(src, target):
        return target.is_not_yet_defined() or src.get_length() == target.get_length()

    @staticmethod
    def is_default(composite):
        return composite.is_not_yet_defined() or composite.num_defined_components() == 0

    @staticmethod
    def is_part(full, part, visited_data_types):
        if isinstance(full, Structure) and isinstance(part, Structure):
            return DWARFDataTypeConflictHandler.is_structure_part(full, part, visited_data_types)
        elif isinstance(full, Union) and isinstance(part, Union):
            return DWARFDataTypeConflictHandler.is_union_part(full, part, visited_data_types)
        else:
            return False

    @staticmethod
    def is_structure_part(full, part, visited_data_types):
        if full.get_length() != part.get_length():
            return False
        for dtc in part.defined_components():
            if not DWARFDataTypeConflictHandler.is_member_field_partially_compatible(dtc, full, visited_data_types):
                return False
        return True

    @staticmethod
    def is_union_part(full, part, visited_data_types):
        if full.get_length() < part.get_length():
            return False
        for dtc in part.defined_components():
            if not DWARFDataTypeConflictHandler.is_member_field_partially_compatible(dtc, full, visited_data_types):
                return False
        return True

    @staticmethod
    def is_member_field_partially_compatible(full_dtc, added_dtc, visited_data_types):
        part_dt = added_dtc.data_type()
        full_dt = full_dtc.data_type()
        if DWARFDataTypeConflictHandler.do_relaxed_compare(part_dt, full_dt, visited_data_types) == ConflictResult.RENAME_AND_ADD:
            return False
        elif part_dt.is_zero_length():
            return True
        else:
            return full_dtc.get_offset() >= added_dtc.get_offset()

    @staticmethod
    def get_best_matching_dtc(structure, match_criteria):
        for dtc in structure.components_containing(match_criteria.offset()):
            if not (dtc.data_type().is_zero_length() or dtc.offset() > match_criteria.offset()):
                return dtc

    @staticmethod
    def do_strict_compare(added_data_type, existing_data_type, visited_data_types):
        if added_data_type == existing_data_type:
            return ConflictResult.USE_EXISTING
        elif not DWARFDataTypeConflictHandler.add_visited(existing_data_type, added_data_type, visited_data_types):
            return ConflictResult.RENAME_AND_ADD

    @staticmethod
    def do_relaxed_compare(added_data_type, existing_data_type, visited_data_types):
        if isinstance(added_data_type, TypeDef) and isinstance(existing_data_type, DataType):
            return DWARFDataTypeConflictHandler.do_relaxed_compare((added_data_type).base_data_type(), existing_data_type, visited_data_types)
        elif isinstance(existing_data_type, TypeDef) and isinstance(added_data_type, DataType):
            return DWARFDataTypeConflictHandler.do_relaxed_compare(added_data_type, (existing_data_type).base_data_type(), visited_data_types)

    @staticmethod
    def get_dtpair_key(data_type1, data_type2):
        return ((long)(hash(data_type1)) << 32) + hash(data_type2)

    @staticmethod
    def add_visited(data_type1, data_type2, visited_data_types):
        key = DWARFDataTypeConflictHandler.get_dtpair_key(data_type1, data_type2)
        return visited_data_types.add(key)

class ConflictResult:
    USE_EXISTING = 0
    REPLACE_EXISTING = 1
    RENAME_AND_ADD = 2

# Note: The following classes are not translated as they seem to be part of the original Java code and might require additional context or information.
class Structure:
    def __init__(self):
        pass

    @property
    def length(self):
        return None

    @property
    def components_containing(self, offset):
        return []

    @property
    def defined_components(self):
        return []

class Union:
    def __init__(self):
        pass

    @property
    def length(self):
        return None

    @property
    def components_containing(self, offset):
        return []

    @property
    def defined_components(self):
        return []
