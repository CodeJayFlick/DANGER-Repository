class CreateEnumAction:
    def __init__(self, plugin):
        super().__init__(plugin, "Enum")

    def create_new_data_type(self, editor_manager, category):
        editor_manager.create_new_enum(category)
