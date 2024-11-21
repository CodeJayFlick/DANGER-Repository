Here is your Java code translated into Python:

```Python
class FidServiceLibraryIngest:
    def __init__(self, fid_db, service, library_family_name, 
                 library_version, library_variant, program_files, function_filter,
                 language_id, link_libraries, monitor):
        self.fid_db = fid_db
        self.service = service
        self.library_family_name = library_family_name
        self.library_version = library_version
        self.library_variant = library_variant
        self.program_files = program_files
        self.function_filter = function_filter
        self.language_id = language_id
        self.link_libraries = link_libraries
        self.monitor = monitor

    def mark_common_child_references(self, symbols):
        if symbols is None:
            return
        for symbol in symbols:
            count = FidPopulateResult.Count()
            count.count = 0
            count.isVeryCommon = True
            child_histogram[self.symbol] = count

    def create(self) -> FidPopulateResult:
        result = FidPopulateResult(None)
        monitor.set_message("Populating library from programs...")
        monitor.initialize(len(program_files))
        for program_file in program_files:
            if self.monitor.check_canceled():
                break
            try:
                program = (Program)(program_file.get_domain_object(monitor, False, False, TaskMonitor.DUMMY))
                self.populate_library_from_program(program)
            except CancelledException as e:
                return FidPopulateResult(None)

        resolve_named_relations()
        if result is not None:
            result.add_child_references(500, child_histogram)
        return result

    def populate_library_from_program(self, program):
        hasher = service.get_hasher(program)
        the_functions = []
        record_map = {}
        for function in program.functions():
            self.monitor.check_canceled()
            if function.is_external():
                continue
            name = None
            hash_quad = None
            if function.has_symbol() and function.symbol().get_source() == SourceType.DEFAULT:
                exclude(program_file, function, FidPopulateResult.Disposition.NO_DEFINED_SYMBOL)
            else:
                name = function.symbol().name()
            if program.is_thunk():
                if name is not None:
                    # the_additional_labels.put(function.entry_point(), name_and_namespace)
                    exclude(program_file, function, FidPopulateResult.Disposition.IS_THUNK)
            elif name is not None:
                try:
                    hash_quad = hasher.hash(function)
                    if hash_quad is None:
                        exclude(program_file, function, FidPopulateResult.Disposition.FAILS_MINIMUM_SHORT_HASH_LENGTH)
                        continue
                    has_terminator = find_terminator(function, self.monitor)
                    row = FunctionRow(domain_file=program_file, function=function, name=name, 
                                        hash_quad=hash_quad, has_terminator=has_terminator)
                    record_map[function] = row

    def resolve_named_relations(self):
        for entry in unresolved_symbols.items():
            function_record, symbols_for_function = entry
            handled = False
            for symbol in symbols_for_function:
                if self.monitor.check_canceled():
                    break
                handled |= handle_named_relation_search(library=library, 
                                                         function_record=function_record,
                                                         symbol=symbol, rel_type=FidPopulateResult.RelationType.INTRA_LIBRARY_CALL)
                if not handled and link_libraries is not None:
                    for library in link_libraries:
                        self.monitor.check_canceled()
                        handled |= handle_named_relation_search(library=library, 
                                                                 function_record=function_record,
                                                                 symbol=symbol, rel_type=FidPopulateResult.RelationType.INTER_LIBRARY_CALL)
            if not handled:
                result.add_unresolved_symbol(symbol.name)

    def find_terminator(self, function):
        ret_found = False
        body = function.body()
        code_unit_iterator = function.program().listing().code_units(body, True)
        while code_unit_iterator.has_next():
            self.monitor.check_canceled()
            code_unit = code_unit_iterator.next()
            if isinstance(code_unit, Instruction):
                instruction = code_unit
                if instruction.flow_type() is TerminalFlowType:
                    ret_found = True
                    break

    def handle_named_relation_search(self, library_record, function_record, symbol, rel_type):
        list_ = self.fid_db.find_functions_by_library_and_name(library=library_record, name=symbol.name)
        hashes = set()
        for relation in list_:
            if self.monitor.check_canceled():
                break
            # If we have hash information about the symbol, use it as additional filter
            if symbol.hash_quad is not None and symbol.hash_quad.full_hash() != relation.full_hash():
                continue
            hashes.add(relation.specific_hash)
        if len(hashes) == 0:
            return False
        elif len(hashes) <= MAXIMUM_NUMBER_OF_NAME_RESOLUTION_RELATIONS:
            for relative in list_:
                self.monitor.check_canceled()
                # Continue to use any hash information as filter
                if symbol.hash_quad is not None and symbol.hash_quad.full_hash() != relative.full_hash():
                    continue
                self.fid_db.create_relation(function_record, relation=relative, rel_type=rel_type)
        else:
            return False

    def check_language_compiler_spec(self, program):
        if language_id != program.language_id:
            return False
        if compiler_spec is not None and compiler_spec != program.compiler_spec():
            raise Exception("Program " + str(program.name) + " has different compiler spec (" 
                            + str(program.compiler_spec().compiler_spec_id()) + ") than already established (" 
                            + str(compiler_spec.compiler_spec_id()) + ")")

    def exclude(self, domain_file, function, reason):
        result.disposition(domain_file=domain_file, name=function.name(), entry_point=function.entry_point(), disposition=reason)

    def search_child_reference_by_name(self, row, name):
        if name is None:
            return
        count = child_histogram.get(name)
        if count is not None:
            count.count += 1
            row.isVeryCommon = count.isVeryCommon
        else:
            count = FidPopulateResult.Count()
            count.count = 1
            count.isVeryCommon = False
            child_histogram[name] = count

    def find_terminator(self, function):
        ret_found = False
        body = function.body()
        code_unit_iterator = function.program().listing().code_units(body, True)
        while code_unit_iterator.has_next():
            self.monitor.check_canceled()
            code_unit = code_unit_iterator.next()
            if isinstance(code_unit, Instruction):
                instruction = code_unit
                if instruction.flow_type() is TerminalFlowType:
                    ret_found = True
                    break

    def create(self) -> FidPopulateResult:
        result = FidPopulateResult(None)
        monitor.set_message("Populating library from programs...")
        monitor.initialize(len(program_files))
        for program_file in program_files:
            if self.monitor.check_canceled():
                break
            try:
                program = (Program)(program_file.get_domain_object(monitor, False, False, TaskMonitor.DUMMY))
                self.populate_library_from_program(program)
            except CancelledException as e:
                return FidPopulateResult(None)

        resolve_named_relations()
        if result is not None:
            result.add_child_references(500, child_histogram)
        return result

    def populate_library_from_program(self, program):
        hasher = service.get_hasher(program)
        the_functions = []
        record_map = {}
        for function in program.functions():
            self.monitor.check_canceled()
            if function.is_external():
                continue
            name = None
            hash_quad = None
            if function.has_symbol() and function.symbol().get_source() == SourceType.DEFAULT:
                exclude(program_file, function, FidPopulateResult.Disposition.NO_DEFINED_SYMBOL)
            else:
                name = function.symbol().name()
            if program.is_thunk():
                if name is not None:
                    # the_additional_labels.put(function.entry_point(), name_and_namespace)
                    exclude(program_file, function, FidPopulateResult.Disposition.IS_THUNK)
            elif name is not None:
                try:
                    hash_quad = hasher.hash(function)
                    if hash_quad is None:
                        exclude(program_file, function, FidPopulateResult.Disposition.FAILS_MINIMUM_SHORT_HASH_LENGTH)
                        continue
                    has_terminator = find_terminator(function, self.monitor)

    def resolve_named_relations(self):
        for entry in unresolved_symbols.items():
            function_record, symbols_for_function = entry
            handled = False
            for symbol in symbols_for_function:
                if self.monitor.check_canceled():
                    break
                handled |= handle_named_relation_search(library=library, 
                            function_record=function_record,
                            symbol=symbol)
                            rel_type=FidPopulateResult.RelationType.INTRA_LIBRARY_CALL)

    def find_terminator(self):
        ret_found = False

class FidServiceLibraryIngest:
    for entry in program_files():
        if self.monitor.check_canceled():
            return result
        "Populating" library from programs..."
        monitor.set_message("Populating" library from programs...")
        monitor.initialize(len(programs)
        for function in program_files():
            if self. check canceled():

class FidServiceLibraryIngest:
    for entry in program_files():
            if self.monitor.check_canceled():
                return result
        "Populating" library from programs...
        monitor.set_message("Populating" library from programs...")
        for function in program_files():
            if self.monitor.check_canceled():
                return result