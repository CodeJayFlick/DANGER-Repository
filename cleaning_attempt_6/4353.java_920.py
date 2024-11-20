class CreateNamespaceAction:
    def __init__(self, plugin, group, sub_group):
        super().__init__("Create Namespace", plugin.name)
        self.menu_data = MenuData(["Create Namespace"], group)
        self.menu_data.set_menu_subgroup(sub_group)
        self.set_popup_menu_data(self.menu_data)
        self.enabled = False

    def is_enabled_for_context(self, context):
        selection_paths = context.get_selected_symbol_tree_paths()
        if len(selection_paths) != 1:
            return False
        object_ = selection_paths[0].get_last_component()
        if isinstance(object_, SymbolNode):
            symbol_node = object_
            symbol = symbol_node.symbol
            symbol_type = symbol.symbol_type
            if symbol_type == "FUNCTION":
                return not symbol.is_external
            elif symbol_type in ["NAMESPACE", "CLASS", "LIBRARY"]:
                return True
        elif isinstance(object_, NamespaceCategoryNode):
            return True
        else:
            return False

    def action_performed(self, context):
        tree = context.get_context_object()
        if tree.is_filtered():
            Msg.show_warn(self.__class__, tree, "Create Namespace Not Allowed", 
                          "Cannot create namespace while the tree is filtered!")
            return
        self.create_namespace(context)

    def create_namespace(self, context):
        selection_paths = context.get_selected_symbol_tree_paths()
        program = context.get_program()
        parent = program.global_namespace
        node = selection_paths[0].get_last_component()

        if isinstance(node, SymbolNode):
            symbol = node.symbol
            parent = symbol.object
            if parent is None:
                return  # assume selected symbol has been deleted

        new_namespace_name = self.create_namespace(program, parent)
        if new_namespace_name is None:
            return  # error occurred

        program.flush_events()
        context.get_symbol_tree().start_editing(node, new_namespace_name)

    def create_namespace(self, program, parent):
        namespace_name = "NewNamespace"
        transaction_id = program.start_transaction("Create Namespace")
        try:
            symbol_table = program.symbol_table
            one_up = 0
            while True:
                try:
                    namespace = symbol_table.create_namespace(parent, namespace_name, SourceType.USER_DEFINED)
                    break
                except DuplicateNameException as e:
                    namespace_name = f"NewNamespace({one_up+1})"
                except InvalidInputException as e:
                    Msg.debug(self.__class__, "Failed to create namespace: " + str(e))
                    return None

        finally:
            program.end_transaction(transaction_id, True)

        return namespace_name
