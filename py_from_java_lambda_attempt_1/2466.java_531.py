Here is the translation of the Java code into Python:

```Python
class DBTraceFunctionSymbolView:
    def __init__(self, manager):
        super().__init__(manager, 'FUNCTION', manager.function_store)

    def assert_proper_space(self, expected, body):
        if not expected.is_memory_space():
            raise ValueError("Function must be in memory space")
        for rng in body:
            if rng.get_address_space() != expected:
                raise ValueError(
                    "Function body must be in same space as entry point")

    def do_validate_parent_and_entry(self, proposed, entry_point):
        if proposed is None:
            return self.manager.global_namespace
        program = self.manager.trace.get_program_view()
        if not SymbolType.FUNCTION.is_valid_address(program, entry_point):
            raise ValueError("Invalid function entry point: " + str(entry_point))
        if not SymbolType.FUNCTION.is_valid_parent(program, proposed, entry_point, False):
            raise ValueError("Invalid function namespace: " + str(proposed))
        return proposed

    def do_validate_source(self, proposed, name, entry_point):
        if not SymbolType.FUNCTION.is_valid_source_type(proposed, entry_point):
            raise ValueError("Invalid function source type: " + str(proposed))
        return proposed

    def do_validate_name(self, proposed, entry_point, source):
        if source == SourceType.DEFAULT:
            return ""
        # TODO: Do entryPoint and source no longer matter? (see commit 898da2b)
        SymbolUtilities.validate_name(proposed)
        return proposed

    def assert_not_overlapping(self, exclude, entry_point, span, body) -> None:
        for rng in body:
            for overlap in self.manager.functions.get_intersecting(span, None, rng, False, True):
                if overlap != exclude:
                    raise OverlappingFunctionException(entry_point,
                                                        new OverlappingNamespaceException(rng.min_address(),
                                                                                        rng.max_address()))

    def add(self, lifespan: Range[Long], entry_point: Address, body: AddressSetView, name: str, thunked: TraceFunctionSymbol, parent: TraceNamespaceSymbol, source: SourceType) -> DBTraceFunctionSymbol:
        if not name or len(name) == 0 or SymbolUtilities.is_reserved_dynamic_label_name(name,
                                                                                          self.manager.trace.get_base_address_factory()):
            source = SourceType.DEFAULT
            name = ""
        else:
            DBTraceSymbolManager.assert_valid_name(name)

        if not "".equals(name) and source == SourceType.DEFAULT:
            raise ValueError("Cannot create DEFAULT function with non-default name")

        if not body.contains(entry_point):
            raise ValueError("Function body must contain the entry point")
        self.assert_proper_space(entry_point.get_address_space(), body)
        try:
            dbns_parent = parent if parent is None else self.manager.assert_is_mine(parent)
            self.manager.assert_valid_thread_address(None, entry_point)

            if thunked and name == thunked.name():
                source = SourceType.DEFAULT
                name = ""

            self.assert_not_overlapping(None, entry_point, lifespan, body)
            dbns_parent = self.do_validate_parent_and_entry(dbns_parent, entry_point)
            source = self.do_validate_source(source, name, entry_point)
            name = self.do_validate_name(name, entry_point, source)

            to_promote = self.manager.labels.get_child_with_name_at(name,
                                                                     DBTraceUtils.lower_endpoint(lifespan), None, entry_point, dbns_parent)
            if to_promote and to_promote.lifespan == lifespan:
                to_promote.delete()

            function = self.store.create()
            function.set(lifespan, entry_point, name, thunked, dbns_parent, source)
            function.do_create_return_parameter()
            for rng in body:
                self.manager.put_id(lifespan, None, rng, function.id)

            cache_for_at.notify_new_entries(lifespan, body, function)

            self.manager.trace.set_changed(
                TraceChangeRecord(TraceSymbolChangeType.ADDED, None, function))
            return function

    @staticmethod
    def get_calling_convention_names(cs):
        named_ccs = cs.get_calling_conventions()
        names = ArrayList(len(named_ccs) + 2)
        names.add(Function.UNKNOWN_CALLING_CONVENTION_STRING)
        names.add(Function.DEFAULT_CALLING_CONVENTION_STRING)
        for model in named_ccs:
            names.add(model.name)
        return names

    def get_calling_convention_names(self):
        # TODO: Allow for user-selected compiler spec(s)
        return self.get_calling_convention_names(self.manager.trace.base_compiler_spec)

    def get_default_calling_convention(self):
        cs = self.manager.trace.base_compiler_spec
        if cs is None:
            return None
        return cs.default_calling_convention

    def get_calling_convention(self, name: str) -> PrototypeModel:
        cs = self.manager.trace.base_compiler_spec
        if cs is None:
            return None
        if Function.UNKNOWN_CALLING_CONVENTION_STRING == name:
            return None
        if Function.DEFAULT_CALLING_CONVENTION_STRING == name:
            return cs.default_calling_convention
        return cs.get_calling_convention(name)

    def get_calling_conventions(self) -> PrototypeModelArray:
        cs = self.manager.trace.base_compiler_spec
        if cs is None:
            return EMPTY_MODEL_LIST
        return cs.get_calling_conventions()

def get_referenced_variable(function: Function, instr_addr: Address, storage_addr: Address,
                             size: int, is_read: bool, language: Language) -> Variable:
    variables = function.all_variables

    param_candidate = None
    local_candidates = None
    first_candidate = None

    size = min(1, size)
    register = language.get_register(storage_addr, size)

    for var in variables:
        storage = var.variable_storage

        if (register and storage.intersects(register)) or (register is None and storage.contains(storage_addr)):
            if isinstance(var, Parameter):
                param_candidate = var
            elif first_candidate is not None:
                local_candidates = ArrayList() if local_candidates is None else local_candidates
                local_candidates.add(first_candidate)
            else:
                first_candidate = var

    use_offset = instr_addr.subtract(function.entry_point).value
    if is_read:
        if use_offset == 0:
            return param_candidate
        --use_offset

    if use_offset < 0:
        # A bit of a hack to deal with negative offsets (from function entry)
        use_offset = max_value - use_offset

    if local_candidates is None:
        if first_candidate is not None:
            var_first_use = first_candidate.first_use_offset
            if var_first_use < 0:
                var_first_use = max_value - var_first_use
            if var_first_use <= use_offset:
                return first_candidate
        else:
            return None

    best_var = None
    best_first_use = 0
    for var in local_candidates:
        var_first_use = var.first_use_offset
        if var_first_use < 0:
            var_first_use = max_value - var_first_use
        if var_first_use <= use_offset and (best_var is None or best_first_use < var_first_use):
            best_var = var
            best_first_use = var_first_use

    if best_var is None:
        return param_candidate
    return best_var
```

Please note that this translation was done manually, so there might be some errors.