Here is the translation of the Java code into Python:

```Python
class DBTraceProgramViewFunctionManager:
    def __init__(self, program):
        self.program = program
        self.functions = program.trace.get_symbol_manager().functions()
        self.global_namespace = program.trace.get_symbol_manager().get_global_namespace()

    def get_program(self):
        return self.program

    def get_function_tag_manager(self):
        # TODO: Implement this method
        pass

    def get_calling_convention_names(self):
        return self.functions.get_calling_convention_names()

    def get_default_calling_convention(self):
        return self.functions.get_default_calling_convention()

    def get_calling_convention(self, name):
        return self.functions.get_calling_convention(name)

    def get_calling_conventions(self):
        return self.functions.get_calling_conventions()

    def create_function(self, name, entry_point, body, source_type):
        try:
            return self.functions.create(self.program.snap, entry_point, body, name, None, self.global_namespace, source_type)
        except InvalidInputException as e:
            # TODO: Why not just declare this as thrown???
            raise RuntimeError("Unexpected for default named function", e)

    def create_thunk_function(self, name, namespace, entry_point, body, thunked_function, source_type):
        try:
            return self.functions.create(self.program.snap, entry_point, body, name,
                                          validate_thunked(thunked_function), validate_parent(namespace), source_type)
        except InvalidInputException as e:
            # TODO: Why not just declare this as thrown???
            raise RuntimeError("Unexpected for default named function", e)

    def get_function_count(self):
        return self.functions.size(False)  # NOTE: May include those not at this snap

    def remove_function(self, entry_point):
        try:
            with LockHold(self.program.trace.lock_write()):
                function = self.get_function_at(entry_point)
                if function is None:
                    return False
                function.delete()
                return True
        except InvalidInputException as e:
            # TODO: Why not just declare this as thrown???
            raise RuntimeError("Unexpected for default named function", e)

    def get_function_at(self, entry_point):
        if not isinstance(entry_point.get_address_space(), MemorySpace):
            return None

        for snap in self.program.viewport.get_ordered_snaps():
            for func in self.functions.get_at(snap, None, entry_point, False):
                if entry_point.equals(func.entry_point()):
                    return func
                else:
                    return None  # Anything below is occluded by the found function
        return None

    def get_referenced_function(self, address):
        if not isinstance(address.get_address_space(), MemorySpace):
            return None
        referenced_func = self.get_function_at(address)
        if referenced_func is not None:
            return referenced_func
        trace_data = self.program.get_top_code(address,
                                               lambda space, s: space.data().get_containing(s, address))
        if trace_data is None:
            return None
        ref = self.program.trace.get_reference_manager().get_primary_reference_from(trace_data.start_snap(), address, 0)
        return ref.get_to_address() if ref else None

    def get_function-containing(self, addr):
        for func in self.functions.get_at(self.program.snap, None, addr, False):
            return func
        return None

    def get_functions_in_range(self, range, forward=True):
        return iter([func for func in self.functions.intersecting(Range.singleton(self.program.snap), None, range, False, forward)])

    def get_functions(self, start=None, forward=True):
        if start is not None:
            return self.get_functions_in_range(AddressSetView(start, forward), forward)
        else:
            return iter([func for func in self.functions.intersecting(Range.singleton(self.program.snap), None, AddressRangeImpl(0, float('inf')), False, forward)])

    def get_functions_no_stubs(self, start=None, forward=True):
        if start is not None:
            return self.get_functions_in_range(AddressSetView(start, forward), forward)
        else:
            return iter([func for func in self.functions.intersecting(Range.singleton(self.program.snap), None, AddressRangeImpl(0, float('inf')), False, forward) if not func.is_thunk()])

    def get_external_functions(self):
        return EmptyFunctionIterator.INSTANCE

    def is_in_function(self, addr):
        # TODO: Could use idMap directly to avoid loading the function
        return self.get_function_containing(addr) is not None

    def move_address_range(self, from_addr, to_addr, length, monitor=None):
        raise NotImplementedError()

    def delete_address_range(self, start_addr, end_addr, monitor=None):
        for func in self.functions.intersecting(AddressRangeImpl(start_addr, end_addr), True):
            try:
                with LockHold(self.program.trace.lock_write()):
                    if not monitor.check_canceled():
                        func.delete()
            except InvalidInputException as e:
                # TODO: Why not just declare this as thrown???
                raise RuntimeError("Unexpected for default named function", e)

    def set_program(self, program):
        raise NotImplementedError()

    def program_ready(self, open_mode, current_revision, monitor=None):
        raise NotImplementedError()

    def invalidate_cache(self, all=False):
        raise NotImplementedError()

    def get_functions_overlapping(self, set):
        return iter([func for func in self.functions.intersecting(set.iterator(True))])

    def get_referenced_variable(self, instr_addr, storage_addr, size, is_read):
        function = self.get_function_containing(instr_addr)
        if function is None:
            return None
        return DBTraceFunctionSymbolView.get_referenced_variable(function, instr_addr, storage_addr, size, is_read, self.program.language)

    def get_function(self, key):
        return self.functions.get_by_key(key)


class EmptyFunctionIterator:
    INSTANCE = iter([])