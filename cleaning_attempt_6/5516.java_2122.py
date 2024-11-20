class RegisterFieldFactory:
    FIELD_NAME = "Register"
    REGISTER_GROUP_NAME = "Register Field"

    DISPLAY_HIDDEN_REGISTERS_OPTION_NAME = f"{REGISTER_GROUP_NAME}{Options.DELIMITER}Display Hidden Registers"
    DISPLAY_DEFAULT_REGISTER_VALUES_OPTION_NAME = f"{REGISTER_GROUP_NAME}{Options.DELIMITER}Display Default Register Values"

    def __init__(self):
        super().__init__(FIELD_NAME)

    @classmethod
    def newInstance(cls, format_model: 'FieldFormatModel', highlight_provider: 'HighlightProvider',
                    tool_options: 'ToolOptions', field_options: 'ToolOptions') -> 'RegisterFieldFactory':
        return cls(format_model, highlight_provider, tool_options, field_options)

    def getField(self, proxy_obj: object, var_width: int) -> 'ListingField':
        obj = proxy_obj.get_object()
        if not self.enabled or not isinstance(obj, Function):
            return None
        x = self.start_x + var_width

        function = (Function)(obj)
        set_registers = self.get_set_registers(function)

        if len(set_registers) == 0:
            return None

        register_strings = self.get_register_strings(function, set_registers)
        return self.getText_field(register_strings, proxy_obj, x)

    def get_set_registers(self, function: 'Function') -> list['Register']:
        program = function.get_program()
        program_context = program.get_program_context()

        registers_with_values = [register for register in program_context.get_registers() if
                                 not register.is_hidden() or self.show_hidden_registers]

        set_registers = []
        for register in registers_with_values:
            reg_val = (self.show_default_register_values and
                       program_context.get_register_value(register, function.entry_point)) or \
                      program_context.get_non_default_value(register, function.entry_point)

            if reg_val is not None and reg_val.has_value():
                set_registers.append(register)
        return set_registers

    def get_register_strings(self, function: 'Function', set_registers: list['Register']) -> list[str]:
        strings = [f"assume {register.name} = 0x{value.to_bytes(4, byteorder='little').hex()}" for register in
                   set_registers]
        return strings

    def getFieldLocation(self, listing_field: 'ListingField', index: int, field_num: int,
                          program_location: object) -> tuple[int, int]:
        obj = listing_field.get_proxy().get_object()
        if isinstance(obj, Function) and isinstance(program_location, RegisterFieldLocation):
            return (index, field_num, program_location.row(), program_location.char_offset())
        return None

    def getProgramLocation(self, row: int, col: list['ListingField']) -> object:
        obj = col.get_proxy().get_object()
        if isinstance(obj, Function):
            function = (Function)(obj)
            set_registers = self.get_set_registers(function)

            register_names = [register.name for register in set_registers]
            return RegisterFieldLocation(function.get_program(), function.entry_point,
                                          register_names, row, col)
        return None

    def acceptsType(self, category: int, proxy_object_class: type) -> bool:
        if not Function.class.isAssignableFrom(proxy_object_class):
            return False
        return category == FieldFormatModel.FUNCTION

    def getDefaultColor(self) -> object:
        return OptionsGui.REGISTERS.get_default_color()

    def fieldOptionsChanged(self, options: 'ToolOptions', option_name: str,
                             old_value: object, new_value: object) -> None:
        super().fieldOptionsChanged(options, option_name, old_value, new_value)

        if option_name == self.DISPLAY_HIDDEN_REGISTERS_OPTION_NAME:
            self.show_hidden_registers = bool(new_value)
            self.model.update()
        elif option_name == self.DISPLAY_DEFAULT_REGISTER_VALUES_OPTION_NAME:
            self.show_default_register_values = bool(new_value)
            self.model.update()

    def displayOptionsChanged(self, options: 'ToolOptions', option_name: str,
                              old_value: object, new_value: object) -> None:
        super().displayOptionsChanged(options, option_name, old_value, new_value)

        if option_name == OptionsGui.REGISTERS.get_color_option_name():
            self.reg_color = (Color)(new_value)
            self.model.update()

    def getRegisterNames(self, set_registers: list['Register']) -> list[str]:
        return [register.name for register in set_registers]
