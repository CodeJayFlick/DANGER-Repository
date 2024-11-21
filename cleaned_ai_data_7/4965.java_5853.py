class PdbInfoCodeView:
    MAGIC = (0x454e424d << 16) | 10

    def __init__(self):
        self.magic = None
        self.offset = None
        self.sig = None
        self.age = None
        self.pdbName = None
        self.pdbPath = None

    @classmethod
    def is_match(cls, reader, offset):
        value = int.from_bytes(reader.read(offset), 'big')
        return cls.MAGIC == value

    @classmethod
    def read(cls, reader, offset):
        result = PdbInfoCodeView()
        reader.seek(offset)
        result.magic = reader.read(4)
        result.offset = int.from_bytes(reader.read(4), 'big')
        result.sig = int.from_bytes(reader.read(4), 'big')
        result.age = int.from_bytes(reader.read(4), 'big')
        pdb_path_length = int.from_bytes(reader.read(4), 'big')
        result.pdbPath = reader.read(pdb_path_length).decode('ascii')
        result.pdbName = os.path.basename(result.pdbPath)
        return result

    def is_valid(self):
        return len(self.magic) == 4 and self.pdbName != ''

    def serialize_to_options(self, options):
        options['PDB_VERSION'] = ''.join(map(lambda x: chr(x), self.magic))
        options['PDB_SIGNATURE'] = hex(self.sig)[2:]
        options['PDB_AGE'] = hex(self.age)[2:]
        options['PDB_FILE'] = self.pdbName

    def to_data_type(self):
        struct = {'name': 'PdbInfo', 'fields': []}
        if len(self.magic) > 0:
            struct['fields'].append({'type': 'string', 'length': len(self.magic), 'name': 'signature'})
        struct['fields'].append({'type': 'int', 'name': 'offset'})
        struct['fields'].append({'type': 'int', 'name': 'sig'})
        struct['fields'].append({'type': 'int', 'name': 'age'})
        if len(self.pdbName) > 0:
            struct['fields'].append({'type': 'string', 'length': len(self.pdbName), 'name': 'pdbname'})
        return {'category_path': ['/PDB'], **struct}
