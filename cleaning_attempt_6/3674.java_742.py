import tkinter as tk
from typing import List

class FindReferencesToFieldAction:
    def __init__(self, plugin: 'DataTypeManagerPlugin') -> None:
        super().__init__()
        self.plugin = plugin
        self.name = "Find Uses of Field"
        self.menu_group = "ZVeryLast"  # own group; on the bottom
        self.popup_menu_data = MenuData(["Find Uses of Field..."], None, self.menu_group)
        self.help_location = HelpLocation("LocationReferencesPlugin", "Data_Types")
        self.enabled = True

    def is_enabled_for_context(self, context: 'ActionContext') -> bool:
        if not isinstance(context, DataTypesActionContext):
            return False
        context_object = context.get_context_object()
        gtree = GTree(context_object)
        selection_paths = gtree.get_selection_paths()
        if len(selection_paths) != 1:
            return False
        node = selection_paths[0].get_last_component()
        if not isinstance(node, DataTypeNode):
            return False
        dt_node = DataTypeNode(node)
        data_type = dt_node.get_data_type()
        return isinstance(data_type, Composite)

    def action_performed(self, context: 'ActionContext') -> None:
        gtree = GTree(context.get_context_object())
        selection_paths = gtree.get_selection_paths()
        dt_node = DataTypeNode(selection_paths[0].get_last_component())

        tool = self.plugin.get_tool()
        service = tool.get_service(FindAppliedDataTypesService)
        if service is None:
            Msg.show_error(self, "Missing Plugin", "The FindAppliedDataTypesService is not installed.\nPlease add the plugin implementing this service.")
            return

        composite = dt_node.get_data_type()
        components = [component for component in composite.get_defined_components() if not isinstance(component, BitFieldComponent)]
        names: List[str] = []
        for component in components:
            field_name = component.get_field_name()
            if not field_name:
                continue
            names.append(field_name)

        array = list(names)
        user_choice = OptionDialog.show_input_choice_dialog(None, "Choose Field", f"Find uses of '{composite.name}' field", array, None, tk.QUESTION_MESSAGE)
        if user_choice is None:
            return

        SwingUtilities.invokeLater(lambda: service.find_and_display_applied_data_type_addresses(composite, user_choice))

class MenuData:
    def __init__(self, items: List[str], parent_menu_item=None, menu_group="") -> None:
        self.items = items
        self.parent_menu_item = parent_menu_item
        self.menu_group = menu_group

class HelpLocation:
    def __init__(self, plugin_name: str, help_topic: str) -> None:
        self.plugin_name = plugin_name
        self.help_topic = help_topic

class OptionDialog:
    @staticmethod
    def show_input_choice_dialog(parent_window=None, title="Choose Field", message="", choices=[], default_value=None, icon=tk.QUESTION_MESSAGE):
        # implement this method in Python
        pass  # TODO: implement the dialog logic here

# Note: The following classes are not implemented in Python:
#   - GTree
#   - DataTypeNode
#   - Composite
#   - BitFieldComponent
#   - FindAppliedDataTypesService
