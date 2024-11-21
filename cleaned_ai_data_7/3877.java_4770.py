class EditStructureAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Edit Structure", plugin.name)

    @property
    def popup_menu_data(self):
        return {"path": ["Array"], "label": "Edit Structure..."}

    @property
    def help_location(self):
        return {"topic": "DataTypeEditors", "section": "Structure_Editor"}

    def actionPerformed(self, context):
        program = context.get_program()
        location = context.get_location()
        data_type = self.get_data_type(program, location)
        if isinstance(data_type, Composite):
            self.plugin.data_type_manager_service.edit(data_type)

    def is_enabled_for_context(self, context):
        if not context.has_selection() or context.get_address() is None:
            return False
        program_location = context.get_location()
        program = context.get_program()

        if not (isinstance(program_location, VariableLocation) or isinstance(program_location, VariableCommentFieldLocation)):
            return False

        data_type = self.get_data_type(program, location)
        if data_type and isinstance(data_type, Composite) and not isinstance(data_type, BuiltInDataType):
            return True
        return False

    def get_data_type(self, program, location):
        if program is None:
            return None
        listing = program.get_listing()
        function = listing.get_function_at(location.get_address())
        if function is None:
            return None

        data_type = None

        if isinstance(location, FunctionSignatureFieldLocation):
            data_type = function.get_return_type()
        else:
            variable = self.get_variable(function, location)
            if variable is not None:
                data_type = variable.get_data_type()

        # If the data type is a pointer, dig out what it points to!
        if isinstance(data_type, Pointer):
            data_type = data_type.get_data_type()
        return data_type

    def get_variable(self, function, location):
        if function is None:
            return None
        if isinstance(location, VariableLocation):
            return location.get_variable()
        return None


# Example usage:

class FunctionPlugin:
    pass

plugin = FunctionPlugin()

action = EditStructureAction(plugin)
