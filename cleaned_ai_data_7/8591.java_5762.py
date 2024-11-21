class PdbProgramAttributes:
    def __init__(self, program):
        prop_list = program.get_options(Program.PROGRAM_INFO)
        
        self.pdb_guid = None if not prop_list.contains(PdbParserConstants.PDB_GUID) else str(prop_list.get_string(PdbParserConstants.PDB_GUID))
        self.pdb_age = None if not prop_list.contains(PdbParserConstants.PDB_AGE) else str(prop_list.get_string(PdbParserConstants.PDB_AGE))
        self.pdb_loaded = False if not prop_list.contains(PdbParserConstants.PDB_LOADED) else bool(prop_list.get_boolean(PdbParserConstants.PDB_LOADED, False))
        self.program_analyzed = False if not prop_list.contains(Program.ANALYZED) else bool(prop_list.get_boolean(Program.ANALYZED, False))
        self.pdb_signature = None if not prop_list.contains(PdbParserConstants.PDB_SIGNATURE) else str(prop_list.get_string(PdbParserConstants.PDB_SIGNATURE))
        self.pdb_file = None if not prop_list.contains(PdbParserConstants.PDB_FILE) else str(prop_list.get_string(PdbParserConstants.PDB_FILE))
        self.pdb_version = None if not prop_list.contains(PdbParserConstants.PDB_VERSION) else str(prop_list.get_string(PdbParserConstants.PDB_VERSION))

        self.executable_path = program.get_executable_path()

    def __init__(self, guid=None, age=None, loaded=False, analyzed=False, signature=None, file=None, exec_path=None):
        self.pdb_guid = guid
        self.pdb_age = age
        self.pdb_loaded = loaded
        self.program_analyzed = analyzed
        self.pdb_signature = signature
        self.pdb_file = file
        self.executable_path = exec_path

    def get_pdb_age(self):
        return self.pdb_age

    def get_pdb_age_as_int(self):
        try:
            return int(self.pdb_age, 16)
        except ValueError:
            return 0

    def get_pdb_guid(self):
        return self.pdb_guid

    def get_pdb_signature(self):
        return self.pdb_signature

    def get_pdb_signature_as_int(self):
        try:
            return int(self.pdb_signature, 16)
        except ValueError:
            return 0

    def get_pdb_file(self):
        return self.pdb_file

    def get_pdb_version(self):
        return self.pdb_version

    def is_pdb_loaded(self):
        return self.pdb_loaded

    def get_executable_path(self):
        return self.executable_path

    def is_program_analyzed(self):
        return self.program_analyzed
