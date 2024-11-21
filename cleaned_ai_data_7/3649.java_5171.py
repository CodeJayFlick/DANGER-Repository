class CreateFunctionDefinitionAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Function Definition")

    def create_new_data_type(self, editor_manager, category):
        editor_manager.create_new_function_definition(category)
