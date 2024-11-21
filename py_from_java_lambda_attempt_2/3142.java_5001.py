Here is the translation of the Java code into Python:

```Python
class SharedReturnAnalysisCmd:
    def __init__(self, set, assume_contiguous_functions, consider_conditional_branches):
        super().__init__("Shared Return Analysis", False, True, False)
        self.set = set
        self.assume_contiguous_functions = assume_contiguous_functions
        self.consider_conditional_branches = consider_conditional_branches

    def apply_to(self, obj, monitor):
        program = Program(obj)

        try:
            # Check destination functions within set
            symbol_table = program.get_symbol_table()
            fn_symbols = symbol_table.get_symbols(set, SymbolType.FUNCTION, True)
            while fn_symbols.has_next():
                monitor.check_cancelled()
                s = fn_symbols.next()
                entry = s.get_address()

                self.process_function_jump_references(program, entry, monitor)

            if self.assume_contiguous_functions:
                # assume if checkAllJumpReferences then set is much more than new function starts

                jump_scan_set = AddressSetView()

                fn_symbols = symbol_table.get_symbols(set, SymbolType.FUNCTION, True)
                while fn_symbols.has_next():
                    monitor.check_cancelled()
                    s = fn_symbols.next()
                    self.check_above_function(s, jump_scan_set)

                    self.check_below_function(s, jump_scan_set)

                # Used for caching forward/backward function lookups as we
                # move forward through jump references

                prev_function_after_src = None
                next_function_before_src = None

                ref_mgr = program.get_reference_manager()
                src_iter = ref_mgr.get_references_source_iterator(jump_scan_set, True)
                while src_iter.has_next():
                    monitor.check_cancelled()
                    addr = src_iter.next()
                    flow = None
                    dest_addr = None
                    for ref in ref_mgr.get_references_from(addr):
                        if ref.get_reference_type().is_flow():
                            if flow is not None:
                                break

                            flow = ref.get_reference_type()
                            dest_addr = ref.get_to_address()

                # Reset cached functions if we transition to a different space/overlay
                if prev_function_after_src != Address.NO_ADDRESS and \
                   prev_function_after_src.get_address_space() != addr.get_address_space():
                    prev_function_after_src = None

                if next_function_before_src != Address.NO_ADDRESS and \
                   next_function_before_src.get_address_space() != addr.get_address_space():
                    next_function_before_src = None

                # forward jump
                if dest_addr is not None:
                    if addr.compareTo(dest_addr) < 0:
                        if prev_function_after_src == Address.NO_ADDRESS:
                            continue  # no function after srcAddr

                        if prev_function_after_src is None or \
                           prev_function_after_src.compareTo(addr) <= 0:
                            next_function = self.get_function_after(program, addr)
                            if next_function is not None:
                                prev_function_after_src = next_function.get_entry_point()
                            else:
                                prev_function_after_src = Address.NO_ADDRESS
                        continue

                    if dest_addr.compareTo(prev_function_after_src) >= 0:
                        self.create_function(program, dest_addr, monitor)

                # backward jump
                elif addr.compareTo(dest_addr) > 0:
                    if next_function_before_src == Address.NO_ADDRESS:
                        if prev_function_after_src is None or \
                           addr.compareTo(prev_function_after_src) < 0:
                            continue  # we have not passed lastFunctionAfterSrc - no function before

                        next_function = self.get_function_after(program, src_addr)
                        if next_function is not None:
                            prev_function_after_src = next_function.get_entry_point()
                        else:
                            prev_function_after_src = Address.NO_ADDRESS
                    elif dest_addr.compareTo(next_function_before_src) < 0:
                        continue  # we have passed lastFunctionBefore - no function before

                return True

        except CancelledException as e:
            pass

    def get_function_before(self, program, addr):
        listing = program.get_listing()
        prev_function_iter = listing.get_functions(get_range_before(program, addr), False)
        if prev_function_iter.has_next():
            return prev_function_iter.next()

        return None

    def get_range_before(self, program, addr):
        space = addr.get_address_space()
        min_addr = space.get_min_address()
        if addr.equals(min_addr):
            return AddressSetView()

        try:
            return AddressSetView(min_addr, addr.subtract_no_wrap(1))

        except AddressOverflowException as e:
            raise AssertException(e)

    def get_function_after(self, program, addr):
        listing = program.get_listing()
        next_function_iter = listing.get_functions(get_range_after(program, addr), True)
        if next_function_iter.has_next():
            return next_function_iter.next()

        return None

    def get_range_after(self, program, addr):
        space = addr.get_address_space()
        max_addr = space.get_max_address()
        if addr.equals(max_addr):
            return AddressSetView()

        try:
            return AddressSetView(addr.add_no_wrap(1), max_addr)

        except AddressOverflowException as e:
            raise AssertException(e)

    def create_function(self, program, entry, monitor):
        if program.get_function_manager().get_function_at(entry) is not None:
            self.process_function_jump_references(program, entry, monitor)
        else:
            analysis_mgr = AutoAnalysisManager.get_analysis_manager(program)
            analysis_mgr.create_function(entry, False)

    def check_above_function(self, function_symbol, jump_scan_set):
        program = function_symbol.get_program()
        addr = function_symbol.get_address()
        prev_function = self.get_function_before(program, addr)
        if prev_function is not None:
            # Must scan everything from previous function down to functionSymbol
            jump_scan_set.add_range(prev_function.get_entry_point(), addr)

    def check_below_function(self, function_symbol, jump_scan_set):
        program = function_symbol.get_program()
        entry = function_symbol.get_address()

        if self.assume_contiguous_functions:
            # Must scan everything above function

            jump_scan_set.add_range(entry.subtract_no_wrap(1), entry)

    def process_function_jump_references(self, program, entry, monitor):
        fn_ref_list = get_jump_refs_to_function(program, entry, monitor)
        for ref in fn_ref_list:
            if not ref.get_reference_type().is_flow():
                continue

            # since reference fixup will occur when flow override is done,
            # avoid concurrent modification during reference iterator use
            # by building list of jump references
    def get_jump_refs_to_function(self, program, entry, monitor):
        fn_ref_list = None
        ref_iter = program.get_reference_manager().get_references_to(entry)
        while ref_iter.has_next():
            if not ref_iter.next().get_reference_type().is_flow():
                continue

            if fn_ref_list is None:
                fn_ref_list = []

            fn_ref_list.append(ref)

    def get_single_flow_reference_from(self, instr):
        flow_count = 0
        for ref in instr.get_references_from():
            if not ref.is_memory_reference() or not ref.get_reference_type().is_flow():
                continue

            if ++flow_count > 1:
                return None  # only change if single flow

            return ref