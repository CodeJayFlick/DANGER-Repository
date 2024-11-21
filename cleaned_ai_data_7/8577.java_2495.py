class RegisterRelativeSymbolApplier:
    def __init__(self, applicator, iter):
        self.applicator = applicator
        self.iter = iter
        abstract_symbol = next(iter)
        if not isinstance(abstract_symbol, AbstractRegisterRelativeAddressMsSymbol):
            raise AssertionError(f"Invalid symbol type: {abstract_symbol.__class__.__name__}")
        self.symbol = abstract_symbol

    def apply(self) -> None:
        print("Cannot apply RegisterRelativeSymbolApplier directly to program")

    def apply_to(self, applier: 'FunctionSymbolApplier') -> None:
        if not self.applicator.get_pdb_applicator_options().apply_function_variables():
            return
        if isinstance(applier, FunctionSymbolApplier):
            function_symbol_applier = applier
            create_function_variable(function_symbol_applier)

    def create_function_variable(self, applier: 'FunctionSymbolApplier') -> bool:
        Objects.requireNonNull(applier)
        function = applier.get_function()
        if function is None:
            self.applicator.append_log_msg("Could not create stack variable for non-existent function.")
            return False
        register_name = self.symbol.get_register_name_string()
        register = self.applicator.get_register(register_name)
        sp = self.applicator.get_program().get_compiler_spec().get_stack_pointer()
        if register != sp:
            return False

        register_change = applier.get_register_prolog_change(register)

        stack_frame = function.get_stack_frame()

        base_param_offset = applier.get_base_param_offset()
        frame_size = applier.get_current_frame_size()
        relative_offset = self.symbol.get_offset() + register_change
        if register_change is None:
            register_change = 0

        offset = int(relative_offset & 0xffffffff)
        data_type_applier = self.applicator.get_type_applier(self.symbol.get_type_record_number())
        dt = data_type_applier.get_data_type()
        if dt is not None:
            try:
                variable = stack_frame.get_variable_containing(offset)
                if variable is None or variable.get_stack_offset() != offset:
                    if variable is not None:
                        stack_frame.clear_variable(variable.get_stack_offset())

                    try:
                        variable = stack_frame.create_variable(self.symbol.name, offset, dt,
                                                              SourceType.IMPORTED)
                    except DuplicateNameException as e:
                        variable = stack_frame.create_variable(f"{self.symbol.name}@{hex(offset)}", offset, dt,
                                                              SourceType.IMPORTED)

                else:
                    variable.set_data_type(dt, False, True, SourceType.ANALYSIS)
                    try:
                        variable.set_name(self.symbol.name, SourceType.IMPORTED)
                    except DuplicateNameException as e:
                        variable.set_name(f"{self.symbol.name}@{hex(offset)}", SourceType.IMPORTED)

            except (InvalidInputException, DuplicateNameException) as e:
                self.applicator.append_log_msg(
                    f"Unable to create stack variable {self.symbol.name} at offset {offset} in {function.name}")
                return False
        return True

class FunctionSymbolApplier:
    def __init__(self):
        pass

    @property
    def function(self) -> 'Function':
        raise NotImplementedError("Method not implemented")

    @property
    def get_register_prolog_change(self, register: 'Register') -> int | None:
        raise NotImplementedError("Method not implemented")

    @property
    def base_param_offset(self) -> int:
        raise NotImplementedError("Method not implemented")

    @property
    def current_frame_size(self) -> int:
        raise NotImplementedError("Method not implemented")
