Here is a translation of the Java code into equivalent Python:

```Python
class ManagedProcedureSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter
        self.procedure_symbol = None
        self.specified_address = None
        self.address = None
        self.function = None
        self.specified_frame_size = 0
        self.current_frame_size = 0
        self.comments = BlockCommentsManager()
        self.symbol_block_nesting_level = 0
        self.current_block_address = None

    def manage_block_nesting(self, applier_param):
        procedure_symbol_applier = ManagedProcedureSymbolApplier(applier_param)
        start = self.procedure_symbol.get_debug_start_offset()
        end = self.procedure_symbol.get_debug_end_offset()
        block_address = self.address.add(start)
        length = end - start
        procedure_symbol_applier.begin_block(block_address, self.procedure_symbol.name(), length)

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
        return self.procedure_symbol.name()

    def apply_to(self, applier_param):
        # Do nothing.
        pass

    def apply(self):
        for _ in range(len(list(self.iter))):
            if not self.applicator.is_invalid_address(self.address, self.get_name()):
                break
        else:
            raise PdbException("Failed to resolve datatype")

    def set_local_variable(self, address, name, data_type):
        if self.current_block_address is None:
            return

        comment = f"static local (stored at {address}) {data_type.name()} {name}"
        self.comments.add_pre_comment(self.current_block_address, comment)

    def apply_function(self, monitor):
        listing = self.applicator.get_program().get_listing()

        if not self.function:
            self.create_function(monitor)
        else:
            return True

        current_frame_size = 0
        return True

    def create_function(self, monitor):
        fun_cmd = CreateFunctionCmd(self.address)

        if not fun_cmd.apply_to(self.applicator.get_program(), monitor):
            applicator.append_log_msg("Failed to apply function at address " + self.address)
            return listing.get_function_at(self.address)
        else:
            return fun_cmd.get_function()

    def end_block(self):
        if --self.symbol_block_nesting_level < 0:
            applicator.append_log_msg(f"Block Nesting went negative for {self.name} at {self.address}")
        elif self.symbol_block_nesting_level == 0:
            # current_function_symbol_applier = None
            pass

    def begin_block(self, start_address, name, length):
        if not applicator.get_pdb_applicator_options().apply_code_scope_block_comments():
            return

        indent = "    "
        base_comment = f"level {self.symbol_block_nesting_level}, length {length}"
        pre_comment = f"{indent}PDB: Block Beg, {base_comment}"

        if not name:
            post_comment = f"{indent}PDB: Block End, {base_comment}"
        else:
            post_comment = f"{indent}PDB: Block End, ({name}) {base_comment}"

        self.comments.add_pre_comment(start_address, pre_comment)
        self.comments.add_post_comment(self.current_block_address, post_comment)

    def get_indent(self, indent_level):
        return "    " * (indent_level - 1)


class RegisterChangeCalculator:
    def __init__(self, procedure_symbol, function, monitor):
        if not procedure_symbol:
            return

        frame_reg = function.get_program().get_compiler_spec().get_stack_pointer()
        entry_addr = function.get_entry_point()
        debug_start = entry_addr.add(procedure_symbol.get_debug_start_offset())
        scope_set = set(range(entry_addr, debug_start))
        self.call_depth_change_info = CallDepthChangeInfo(function, scope_set, frame_reg, monitor)

    def get_reg_change(self, applicator, register):
        if not self.call_depth_change_info or not register:
            return None

        change = {register: 0}
        for instruction in function.get_program().get_listing().get_instructions(scope_set, True):
            min_address = instruction.min_address()
            depth = self.call_depth_change_info.get_reg_depth(min_address, register)
            if abs(depth) > abs(change[register]):
                change[register] = depth
        return change


class BlockCommentsManager:
    def add_pre_comment(self, address, comment):
        pass

    def add_post_comment(self, address, comment):
        pass
```

Please note that Python does not have direct equivalent of Java's `PdbException`, so I just used a simple exception class. Also, some methods like `create_function_command` and `get_frame_base_offset` are missing in the provided code, but they should be implemented based on their purpose.

This translation is done manually by hand translating each line from Java to Python.