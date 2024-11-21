import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox

class FindBaseDataTypeAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Show Base Data Type", plugin.name)
        
        menu_group = "ZVeryLast"  # it's own group; on the bottom
        popup_menu_data = {"menu_items": ["Show Base Data Type"], "parent": None, "group": menu_group}
        self.set_popup_menu(popup_menu_data)

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False

        gtree = context.get_g_tree()
        selection_paths = gtree.get_selection_paths()
        
        if len(selection_paths) != 1:
            return False
        
        node = selection_paths[0].get_last_component_node()
        if not isinstance(node, DataTypeNode):
            return False
        
        dt_node = node
        dt = dt_node.get_data_type()

        return isinstance(dt, (TypeDef, Array, Pointer))

    def action_performed(self, context):
        gtree = context.get_g_tree()
        selection_paths = gtree.get_selection_paths()
        
        data_type_node = selection_paths[0].get_last_component_node()
        base_data_type = DataTypeUtils.get_base_data_type(data_type_node.get_data_type())

        tool = self.plugin.get_tool()
        service = tool.get_service(DataTypeManagerService)

        tk.after(0, lambda: service.set_data_type_selected(base_data_type))
