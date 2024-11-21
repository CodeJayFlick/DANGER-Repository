class ChooseDataTypeAction:
    KEY_BINDING = 'VK_T'
    ACTION_NAME = "Choose Data Type"

    def __init__(self):
        pass  # This class does not have any constructor arguments in the original Java code.

    def set_popup_menu_data(self, menu_data: list) -> None:
        if len(menu_data) > 0 and isinstance(menu_data[1], str):
            self.setPopupMenuData(menu_data)
        else:
            raise ValueError("Invalid popup menu data")

    def init_key_stroke(self, key_stroke: str) -> None:
        pass  # This method does not exist in the original Java code.

    def action_performed(self, context: dict) -> None:
        if 'ListingActionContext' in context and isinstance(context['ListingActionContext'], ListingActionContext):
            self.create_data_type(context)
        else:
            raise ValueError("Invalid context")

    def is_enabled_for_context(self, context: dict) -> bool:
        if not ('ListingActionContext' in context and isinstance(context['ListingActionContext'], ListingActionContext)):
            return False
        listing_action_context = context['ListingActionContext']
        has_selection = 'hasSelection' in listing_action_context and listing_action_context['hasSelection']
        location = 'getLocation' in listing_action_context and listing_action_context['getLocation']()
        if not (isinstance(location, ProgramLocation) or isinstance(location, VariableLocation)):
            return False
        plugin_valid_data_location = self.plugin.is_valid_data_location(location)
        return bool(plugin_valid_data_location)

    def create_data_type(self, context: dict) -> None:
        listing_action_context = context['ListingActionContext']
        location = listing_action_context['getLocation']()
        if isinstance(location, VariableLocation):
            max_size = self.get_selected_variable_storage_size(listing_action_context)
            data_type = self.user_selected_data_type(context, max_size)
            if data_type is not None:
                self.plugin.create_data(data_type, context, False, True)

    def get_selected_variable_storage_size(self, context: dict) -> int:
        location = context['ListingActionContext']['getLocation']()
        if isinstance(location, VariableTypeFieldLocation):
            var = (location).getVariable()
            func = var.getFunction()
            if isinstance(var, Parameter) and not func.has_custom_variable_storage():
                return -1
            storage = var.getVariableStorage()
            if storage.is_valid() and not storage.is_stack_storage():
                return storage.size()
        return -1

    def user_selected_data_type(self, context: dict, max_size: int) -> DataType:
        tool = self.plugin.get_tool()
        data_type_manager = context['ListingActionContext']['getProgram']()['DataTypeManager']
        selection_dialog = show_selection_dialog(context, max_size, tool, data_type_manager)
        return selection_dialog.user_chosen_data_type

    def show_selection_dialog(self, context: dict, max_size: int, tool: PluginTool, data_type_manager: DataTypeManager) -> DataTypeSelectionDialog:
        selection_dialog = DataTypeSelectionDialog(tool, data_type_manager, max_size, AllowedDataTypes.FIXED_LENGTH)
        current_data_type = self.plugin.current_data_type(context['ListingActionContext'])
        if current_data_type is not None:
            selection_dialog.set_initial_data_type(current_data_type)
        tool.show_dialog(selection_dialog)
        return selection_dialog

class ListingActionContext(dict):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    def getLocation(self) -> ProgramLocation:
        pass  # This method does not exist in the original Java code.

    @property
    def hasSelection(self) -> bool:
        return False

class DataTypeManager(dict):
    pass  # This class is just a dictionary in Python, so no translation needed.

class PluginTool(dict):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def get_tool(self) -> 'PluginTool':
        return self

    @property
    def current_data_type(self, context: dict) -> DataType:
        pass  # This method does not exist in the original Java code.

class ProgramLocation(dict):
    pass  # This class is just a dictionary in Python, so no translation needed.

class VariableTypeFieldLocation(dict):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    def getVariable(self) -> 'Variable':
        pass  # This method does not exist in the original Java code.

class Parameter(dict):
    pass  # This class is just a dictionary in Python, so no translation needed.

class VariableStorage(dict):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @property
    def size(self) -> int:
        return -1

    @property
    def isValid(self) -> bool:
        pass  # This method does not exist in the original Java code.

    @property
    def isStackStorage(self) -> bool:
        pass  # This method does not exist in the original Java code.
