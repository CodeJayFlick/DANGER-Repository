class CreateExternalLocationAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Create External Location", plugin.name)
        self.set_popup_menu_data([
            {"label": "Create External Location"},
            {"icon": None},
            {"tooltip": "0External"}
        ])
        self.enabled = True

    def is_enabled_for_context(self, context):
        selection_paths = context.selected_symbol_tree_paths
        if len(selection_paths) == 1:
            object_ = selection_paths[0].lastPathComponent()
            if isinstance(object_, (LibrarySymbolNode, ImportsCategoryNode)):
                return True
        return False


class SymbolTreeActionContext:
    def __init__(self):
        self.selected_symbol_tree_paths = []

    @property
    def selected_symbol_tree_paths(self):
        return self._selected_symbol_tree_paths

    @selected_symbol_tree_paths.setter
    def selected_symbol_tree_paths(self, value):
        self._selected_symbol_tree_paths = value


class LibrarySymbolNode:
    def __init__(self, name):
        self.name = name


class ImportsCategoryNode:
    pass


def actionPerformed(context):
    selection_paths = context.selected_symbol_tree_paths
    if len(selection_paths) != 1:
        return

    object_ = selection_paths[0].lastPathComponent()
    if not isinstance(object_, (LibrarySymbolNode, ImportsCategoryNode)):
        return

    external_name = None
    if isinstance(object_, LibrarySymbolNode):
        library_node = object_
        external_name = library_node.name

    dialog = EditExternalLocationDialog(context.get_program(), external_name)
    dialog.set_help_location("SymbolTreePlugin", "CreateExternalLocation")
    plugin.tool().show_dialog(dialog)


class EditExternalLocationDialog:
    def __init__(self, program, name):
        self.program = program
        self.name = name

    @property
    def help_location(self):
        return {"plugin": "SymbolTreePlugin", "topic": "CreateExternalLocation"}

    def set_help_location(self, location):
        self._help_location = location


class SymbolTreePlugin:
    def __init__(self):
        pass

    @property
    def tool(self):
        return None

    @tool.setter
    def tool(self, value):
        self._tool = value
