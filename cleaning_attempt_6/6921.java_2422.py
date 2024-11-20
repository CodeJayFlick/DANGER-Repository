class ListingStructureVariableAction:
    def __init__(self, owner, tool, controller):
        super().__init__(owner, tool, controller)
        self.set_popup_menu_data({
            "Array": ["Auto Create Structure", FunctionPlugin.SET_DATA_TYPE_PULLRIGHT]
        })

    @staticmethod
    def is_enabled_for_context(context):
        if not isinstance(context, ListingActionContext):
            return False

        listing_context = context
        location = listing_context.get_location()
        program = listing_context.get_program()

        if isinstance(location, VariableLocation):
            variable_location = location
            variable = variable_location.get_variable()
            if isinstance(variable, Parameter) and variable.get_auto_parameter_type() == AutoParameterType.THIS:
                return True

            data_type = variable.get_data_type()
        elif isinstance(location, FunctionParameterFieldLocation):
            function_parameter_field_location = location
            parameter = function_parameter_field_location.get_parameter()
            if parameter.get_auto_parameter_type() == AutoParameterType.THIS:
                return True

            data_type = parameter.get_data_type()
        elif isinstance(location, FunctionReturnTypeFieldLocation):
            function_return_type_field_location = location
            func = program.get_function_manager().get_function_at(function_return_type_field_location.get_function_address())
            data_type = func.get_return_type()

        max_pointer_size = program.get_default_pointer_size()
        if not data_type or data_type.get_length() > max_pointer_size:
            return False

        self.adjust_create_structure_menu_text(data_type, variable is None)
        return True
