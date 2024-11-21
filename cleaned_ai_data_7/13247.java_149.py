class ModuleAttribute:
    def __init__(self):
        self.module_name_index = 0
        self.module_flags = 0
        self.module_version_index = 0
        self.requires_count = 0
        self.module_attribute_requires = []
        self.exports_count = 0
        self.module_attribute_exports = []
        self.opens_count = 0
        self.module_attribute_opens = []
        self.uses_count = 0
        self.uses_index = []
        self.provides_count = 0
        self.module_attribute_provides = []

    def get_module_name_index(self):
        return self.module_name_index

    def get_module_flags(self):
        return self.module_flags

    def get_module_version_index(self):
        return self.module_version_index

    def get_requires_count(self):
        return self.requires_count

    def get_exports_count(self):
        return self.exports_count

    def get_opens_count(self):
        return self.opens_count

    def get_uses_count(self):
        return self.uses_count

    def get_provides_count(self):
        return self.provides_count

    def to_data_type(self):
        structure = StructureDataType("Module_attribute", 0)
        structure.add(WORD, "module_name_index", None)
        structure.add(WORD, "module_flags", None)
        structure.add(WORD, "module_version_index", None)
        for i in range(get_requires_count()):
            structure.add(module_attribute_requires[i].to_data_type(), f"requires_{i}", None)
        structure.add(WORD, "exports_count", None)
        for i in range(get_exports_count()):
            structure.add(module_attribute_exports[i].to_data_type(), f"exports_{i}", None)
        structure.add(WORD, "opens_count", None)
        for i in range(get_opens_count()):
            structure.add(module_attribute_opens[i].to_data_type(), f"opens_{i}", None)
        structure.add(WORD, "uses_count", None)
        for i in range(get_uses_count()):
            structure.add(WORD, f"use_{i}", None)
        structure.add(WORD, "provides_count", None)
        for i in range(get_provides_count()):
            structure.add(module_attribute_provides[i].to_data_type(), f"provides_{i}", None)

        return structure


class ModuleAttributeRequires:
    def __init__(self):
        self.requires_index = 0
        self.requires_flags = 0
        self.requires_version_index = 0

    def get_requires_index(self):
        return self.requires_index

    def get_requires_flags(self):
        return self.requires_flags

    def get_requires_version_index(self):
        return self.requires_version_index

    def to_data_type(self):
        structure = StructureDataType("requires", 0)
        structure.add(WORD, "requires_index", None)
        structure.add(WORD, "requires_flags", None)
        structure.add(WORD, "requires_version_index", None)

        return structure


class ModuleAttributeExports:
    def __init__(self):
        self.exports_index = 0
        self.exports_flags = 0
        self.exports_to_count = 0
        self.exports_to_index = []

    def get_exports_index(self):
        return self.exports_index

    def get_exports_flags(self):
        return self.exports_flags

    def get_exports_to_count(self):
        return self.exports_to_count

    def to_data_type(self):
        structure = StructureDataType("exports", 0)
        structure.add(WORD, "exports_index", None)
        structure.add(WORD, "exports_flags", None)
        structure.add(WORD, "exports_to_counts", None)
        for i in range(get_exports_to_count()):
            structure.add(WORD, f"exports_to_index_{i}", None)

        return structure


class ModuleAttributeOpens:
    def __init__(self):
        self.opens_index = 0
        self.opens_flags = 0
        self.opens_to_count = 0
        self.opens_to_index = []

    def get_opens_index(self):
        return self.opens_index

    def get_opens_flags(self):
        return self.opens_flags

    def get_opens_to_count(self):
        return self.opens_to_count

    def to_data_type(self):
        structure = StructureDataType("exports", 0)
        structure.add(WORD, "opens_index", None)
        structure.add(WORD, "opens_flags", None)
        structure.add(WORD, "opens_to_counts", None)
        for i in range(get_opens_to_count()):
            structure.add(WORD, f"opens_to_index_{i}", None)

        return structure


class ModuleAttributeProvides:
    def __init__(self):
        self.provides_index = 0
        self.provides_with_count = 0
        self.provides_with_index = []

    def get_provides_index(self):
        return self.provides_index

    def get_provides_with_count(self):
        return self.provides_with_count

    def to_data_type(self):
        structure = StructureDataType("provides", 0)
        structure.add(WORD, "provides_index", None)
        structure.add(WORD, "provides_with_counts", None)
        for i in range(get_provides_with_count()):
            structure.add(WORD, f"provides_with_index_{i}", None)

        return structure
