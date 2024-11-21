Here is the translation of the Java code into Python:

```Python
class FidService:
    SHORT_HASH_CODE_UNIT_LENGTH = 4
    MEDIUM_HASH_CODE_UNIT_LENGTH = 24
    SCORE_THRESHOLD = 14.6
    MULTINAME_SCORE_THRESHOLD = 30

    def __init__(self):
        self.fid_file_manager = FidFileManager.getInstance()
        self.generator = FunctionBodyFunctionExtentGenerator()
        self.digest_factory = FNV1a64MessageDigestFactory()

    @property
    def short_hash_code_unit_length(self):
        return self.SHORT_HASH_CODE_UNIT_LENGTH

    @property
    def medium_hash_code_unit_length_limit(self):
        return self.MEDIUM_HASH_CODE_UNIT_LENGTH

    @property
    def default_score_threshold(self):
        return self.SCORE_THRESHOLD

    @property
    def default_multi_name_threshold(self):
        return self.MULTINAME_SCORE_THRESHOLD

    def hash_function(self, function: 'Function') -> FidHashQuad:
        code_units = self.generator.calculate_extent(function)
        if len(code_units) < self.short_hash_code_unit_length:
            return None

        fid_hasher = self.get_hasher(function.program)
        hash_triple = fid_hasher.hash(function)

        return hash_triple

    def get_hasher(self, program: 'Program') -> FidHasher:
        language_processor = program.language.processor
        list_instruction_skippers = self.skippers.get(language_processor)
        if not list_instruction_skippers:
            list_instruction_skippers = []
            self.skippers[language_processor] = list_instruction_skippers

        fid_hasher = MessageDigestFidHasher(self.generator, 
                                            self.short_hash_code_unit_length,
                                            self.digest_factory, 
                                            list_instruction_skippers)

        return fid_hasher

    def get_program_seeker(self, program: 'Program', query_service: FidQueryService, score_threshold: float) -> FidProgramSeeker:
        fid_hasher = self.get_hasher(program)
        seeker = FidProgramSeeker(query_service, program, fid_hasher,
                                   self.short_hash_code_unit_length,
                                   self.medium_hash_code_unit_length_limit,
                                   score_threshold)

        return seeker

    def create_new_library_from_programs(self, fid_db: 'FidDB', library_family_name: str, 
                                          library_version: str, library_variant: str, 
                                          program_domain_files: List['DomainFile'], function_filter: Predicate[Pair['Function', FidHashQuad]], 
                                          language_id: LanguageID, link_libraries: List['LibraryRecord'], common_symbols: List[str], monitor: TaskMonitor) -> 'FidPopulateResult':
        ingest = FidServiceLibraryIngest(fid_db, self, library_family_name,
                                         library_version, library_variant,
                                         program_domain_files, function_filter, language_id,
                                         link_libraries, monitor)
        ingest.mark_common_child_references(common_symbols)

        return ingest.create()

    def process_program(self, program: 'Program', query_service: FidQueryService, score_threshold: float, monitor: TaskMonitor) -> List['FidSearchResult']:
        seeker = self.get_program_seeker(program, query_service, score_threshold)
        search_result = seeker.search(monitor)

        return search_result

    def mark_records_auto_pass(self, func_list: List[FunctionRecord], value: bool) -> List[FunctionRecord]:
        res = []
        for func_rec in func_list:
            res.append(func_rec.get_fid_db().set_auto_pass_on_function(func_rec, value))

        return res

    def mark_records_auto_fail(self, func_list: List[FunctionRecord], value: bool) -> List[FunctionRecord]:
        res = []
        for func_rec in func_list:
            res.append(func_rec.get_fid_db().set_auto_fail_on_function(func_rec, value))

        return res

    def mark_records_force_specific(self, func_list: List[FunctionRecord], value: bool) -> List[FunctionRecord]:
        res = []
        for func_rec in func_list:
            res.append(func_rec.get_fid_db().set_force_specific_on_function(func_rec, value))

        return res

    def mark_records_force_relation(self, func_list: List[FunctionRecord], value: bool) -> List[FunctionRecord]:
        res = []
        for func_rec in func_list:
            res.append(func_rec.get_fid_db().set_force_relation_on_function(func_rec, value))

        return res

    def can_process(self, language: Language):
        return self.fid_file_manager.can_query(language)

    def open_fid_query_service(self, language: Language, open_for_update: bool) -> FidQueryService:
        return self.fid_file_manager.open_fid_query_service(language, open_for_update)
```

Please note that this is a direct translation of the Java code into Python.