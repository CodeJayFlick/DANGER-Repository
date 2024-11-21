class ModuleReferenceTable:
    def __init__(self, reader, index, count, imp):
        self.offsets = [0] * int(count)
        for i in range(int(count)):
            self.offsets[i] = reader.read_next_short()
        
        names = []
        for offset in self.offsets:
            lss = imp.get_name_at(offset)
            if not lss or len(lss) == 0: break
            names.append(lss)

        self.names = names

    def get_names(self):
        return self.names

    def get_offsets(self):
        return self.offsets


class ImportedNameTable:
    def __init__(self, imp=None):
        if not hasattr(imp, 'get_name_at'):
            raise ValueError("Imported name table is required")
        self.imp = imp

    def get_name_at(self, offset):
        # This method should be implemented based on the imported name table
        pass


class FactoryBundledWithBinaryReader:
    def __init__(self, reader=None):
        if not hasattr(reader, 'read_next_short'):
            raise ValueError("Binary reader is required")
        self.reader = reader

    def read_next_short(self):
        # This method should be implemented based on the binary reader
        pass


# Example usage:

reader = FactoryBundledWithBinaryReader()
imp = ImportedNameTable()

mrt = ModuleReferenceTable(reader, 0x1234, 5, imp)
print(mrt.get_names())
print(mrt.get_offsets())

