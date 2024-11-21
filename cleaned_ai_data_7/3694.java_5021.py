class SetFavoriteDataTypeAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Set Favorite Data Type", self.plugin.get_name())
        self.set_selected(False)
        menu_data = {"Menu": ["Favorite"], "VeryLast": None}
        self.set_popup_menu_data(menu_data)
        help_location = HelpLocation("DataPlugin", "Favorites")
        self.set_help_location(help_location)
        self.set_enabled(True)

    def is_enabled_for_context(self, context):
        if not isinstance(context, DataTypesActionContext):
            return False

        g_tree = context.get_context_object()
        selection_paths = g_tree.get_selection_paths()

        for path in selection_paths:
            node = path.get_last_component()
            if not isinstance(node, DataTypeNode):
                return False
        is_favorite = selection_paths[0].get_last_component().is_favorite()
        for path in selection_paths:
            node = path.get_last_component()
            if is_favorite != node.is_favorite():
                return False

        self.set_selected(is_favorite)
        return True

    def action_performed(self, context):
        g_tree = context.get_context_object()

        selection_paths = g_tree.get_selection_paths()
        for path in selection_paths:
            node = path.get_last_component()
            if isinstance(node, DataTypeNode):
                toggle_favorite(node, self.is_selected())
