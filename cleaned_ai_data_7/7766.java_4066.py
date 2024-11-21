class CreateEHUnwindMapBackgroundCmd:
    def __init__(self, address: int, count: int):
        super().__init__("unwind_map_entry", address, count)

    def __init__(self, address: int, count: int, validation_options=None, apply_options=None):
        super().__init__("unwind_map_entry", address, count, validation_options, apply_options)

    @property
    def model(self) -> 'EHUnwindModel':
        return self._model

    @model.setter
    def model(self, value: 'EHUnwindModel'):
        self._model = value

    def create_model(self, program):
        if not hasattr(self, '_model') or self._model is None:
            self._model = EHUnwindModel(program, count, self.get_data_address(), validation_options)
        return self._model

    @property
    def apply_options(self) -> 'DataApplyOptions':
        return self._apply_options

    @apply_options.setter
    def apply_options(self, value: 'DataApplyOptions'):
        self._apply_options = value

    def create_associated_data(self):
        try:
            if not hasattr(self, '_model') or self._model is None:
                raise CancelledException("Model is null")
            return self.create_action_refs_and_symbols()
        except CancelledException as e:
            print(f"Error: {e}")
            return False

    def create_action_refs_and_symbols(self):
        if not hasattr(self, '_apply_options') or self._apply_options is None:
            raise CancelledException("Apply options are null")
        program = self.model.get_program()
        result = True
        for unwind_entry_ordinal in range(count):
            monitor.check_cancelled()
            comp_address = self.model.get_component_address_of_action_address(unwind_entry_ordinal)
            action_address = self.model.get_action_address(unwind_entry_ordinal)
            if action_address is None:
                continue  # No unwind action address for this UnwindMap record.
            if not hasattr(self, '_apply_options') or self._apply_options.should_create_label():
                try:
                    symbol = EHDataTypeUtilities.create_symbol_if_needed(program, "Unwind", action_address)
                    if symbol is None:
                        result = False
                except InvalidInputException as e:
                    message = f"Couldn't create name for unwind action at {action_address}."
                    handle_error_message(program, comp_address, message + " " + str(e), message)
                    result = False
            if not hasattr(self, '_apply_options') or self._apply_options.should_create_function():
                success = EHDataTypeUtilities.create_function_if_needed(program, action_address)
                if not success:
                    result = False
        return result

    def create_markup(self):
        return True  # No markup.
