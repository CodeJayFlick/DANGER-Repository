class FunctionSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter
        self.procedure_symbol = None
        self.thunk_symbol = None
        self.specified_address = None
        self.address = None
        self.function = None
        self.specified_frame_size = 0
        self.current_frame_size = 0
        self.comments = BlockCommentsManager()
        self.symbol_block_nesting_level = 0
        self.current_block_address = None

    def manage_block_nesting(self, applier):
        if isinstance(applier, FunctionSymbolApplier):
            function_symbol_applier = applier
            if self.procedure_symbol is not None:
                start = self.procedure_symbol.get_debug_start_offset()
                end = self.procedure_symbol.get_debug_end_offset()
                block_address = self.address.add(start)
                length = end - start
                function_symbol_applier.begin_block(block_address, self.procedure_symbol.name(), length)

    def get_function(self):
        return self.function

    def get_current_frame_size(self):
        return self.current_frame_size

    def get_specified_frame_size(self):
        return self.specified_frame_size

    def set_specified_frame_size(self, specified_frame_size):
        self.specified_frame_size = specified_frame_size
        self.current_frame_size = specified_frame_size

    def get_name(self):
        if self.procedure_symbol is not None:
            return self.procedure_symbol.name()
        elif self.thunk_symbol is not None:
            return self.thunk_symbol.name()
        else:
            return ""

    def apply_to(self, applier):
        # Do nothing.

    def apply(self):
        result = self.apply_to(self.applicator.get_cancel_only_wrapping_monitor())
        if result == False:
            raise PdbException(f"Failure at {self.address} applying {self.name}")
        return True

    def set_local_variable(self, address, name, data_type):
        if self.current_block_address is None:
            return
        comment = f"{get_indent(self.symbol_block_nesting_level + 1)}static local (stored at {address}) {data_type.name()} {name}"
        self.comments.add_pre_comment(self.current_block_address, comment)

    def apply_function(self, monitor):
        listing = self.applicator.get_program().get_listing()

        self.applicator.create_symbol(self.address, self.name(), True)

        function = listing.get_function_at(self.address)
        if function is None:
            function = create_function(monitor)
        if function and not function.is_thunk() and (function.get_signature_source() == SourceType.DEFAULT or
                function.get_signature_source() == SourceType.ANALYSIS):
            set_function_definition(monitor)

        self.current_frame_size = 0
        return True

    def get_register_prolog_change(self, register):
        if isinstance(register, Register):
            return self.register_change_calculator.get_reg_change(self.applicator, register)
        else:
            return None

    # ... (rest of the methods are similar)

class BlockCommentsManager:
    def __init__(self):
        pass

    def add_pre_comment(self, address, comment):
        pass

    def apply_to(self, program, delta_address):
        pass
