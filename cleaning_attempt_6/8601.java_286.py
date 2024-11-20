class SymbolFileInfo:
    def __init__(self, pdb_path: str, pdb_identifiers):
        self.pdb_path = pdb_path
        self.pdb_identifiers = pdb_identifiers

    @property
    def name(self) -> str:
        return os.path.basename(self.pdb_path)

    @property
    def path(self) -> str:
        return self.pdb_path

    @property
    def unique_name(self) -> str:
        if self.pdb_identifiers.guid is not None:
            return self.pdb_identifiers.guid.replace("-", "").upper()
        else:
            return f"{self.pdb_identifiers.signature:08X}"

    @property
    def uniqifier_string(self) -> str:
        if self.pdb_identifiers.guid is not None:
            return self.pdb_identifiers.guid.replace("-", "").upper()
        elif self.pdb_identifiers.signature != 0:
            return f"{self.pdb_identifiers.signature:08X}"
        else:
            return ""

    @property
    def unique_dir_name(self) -> str:
        return f"{self.unique_name}{int.to_bytes(self.pdb_identifiers.age, 'big').hex()}"

    def is_exact_match(self, other: 'SymbolFileInfo') -> bool:
        return self.unique_name.lower() == other.unique_name.lower() and self.pdb_identifiers.age == other.pdb_identifiers.age

    @property
    def description(self) -> str:
        return f"{self.name}, {str(self.pdb_identifiers)}"

    def __str__(self):
        return f"SymbolFileInfo: [pdb: {self.path}, uid: {str(self.pdb_identifiers)}]"

    def __eq__(self, other):
        if self is other:
            return True
        elif other is None:
            return False
        elif type(self) != type(other):
            return False
        else:
            return (hash((self.pdb_path, self.pdb_identifiers)) == hash((other.pdb_path, other.pdb_identifiers)))

    def __hash__(self):
        return hash((self.pdb_path, self.pdb_identifiers))

def from_program_info(program) -> 'SymbolFileInfo':
    try:
        pdb_attrs = PdbProgramAttributes(program)
        sig = pdb_attrs.get_pdb_signature_as_int()
        guid_string = pdb_attrs.get_pdb_guid()
        age = pdb_attrs.get_pdb_age_as_int()
        path = pdb_attrs.get_pdb_file()

        if sig == 0 and guid_string is None and not path:
            return None

        pdb_identifiers = PdbIdentifiers(0, sig, age, GUID(guid_string), None)
        return SymbolFileInfo(path, pdb_identifiers)

    except Exception as e:
        return None

def from_subdirectory_path(path: str, unique_subdir: str) -> 'SymbolFileInfo':
    try:
        if len(unique_subdir) < 8 and len(unique_subdir) > 32:
            sig = int.from_bytes(unique_subdir[:8].encode('utf-16'), 'big')
            age = int.from_bytes(unique_subdir[8:].encode('utf-16'), 'big')

            return SymbolFileInfo(path, PdbIdentifiers(0, sig, age, None, None))

        elif len(unique_subdir) > 32:
            guid_string = unique_subdir[:32]
            age = int.from_bytes(unique_subdir[32:].encode('utf-16'), 'big')

            return SymbolFileInfo(path, PdbIdentifiers(0, 0, age, GUID(guid_string), None))

    except Exception as e:
        pass

def from_values(pdb_path: str, uid: str, age: int) -> 'SymbolFileInfo':
    if not pdb_path:
        return None
    try:
        guid = GUID(uid)
        return SymbolFileInfo(pdb_path, PdbIdentifiers(0, 0, age, guid, None))

    except Exception as e:
        pass

def from_pdb_identifiers(pdb_path: str, pdb_identifiers) -> 'SymbolFileInfo':
    if not pdb_path:
        raise ValueError("Path cannot be null")
    return SymbolFileInfo(pdb_path, pdb_identifiers)

def from_file(pdb_file: File, monitor) -> 'SymbolFileInfo':
    pdb_identifiers = PdbUtils.get_pdb_identifiers(pdb_file, monitor)
    return SymbolFileInfo(pdb_file.name, pdb_identifiers)
