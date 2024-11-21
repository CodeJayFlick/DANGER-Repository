Here is the translation of the given Java code into Python:

```Python
class ShowSymbolReferencesAction:
    def __init__(self, tool, owner):
        super().__init__("Show References to", owner)
        self.tool = tool
        self.set_popup_menu_data(["Show References to"], "0Middle")
        self.install_help_location()
        default_key_stroke = AbstractFindReferencesDataTypeAction.DEFAULT_KEY_STROKE
        self.init_key_stroke(default_key_stroke)

    def init_key_stroke(self, key_stroke):
        if key_stroke is None:
            return

        self.set_key_binding_data(key_stroke)

    def install_help_location(self):
        location_references_service = self.tool.get_service(LocationReferencesService)
        if location_references_service is None:
            # not installed yet; listen for the service to be installed
            self.tool.add_service_listener(self.help_location_service_listener)
            return

        # this action is really just a pass through for the service
        self.set_help_location(location_references_service.get_help_location())

    def help_location_service_removed(self, interface_class, service):
        # don't care
        pass

    def help_location_service_added(self, interface_class, service):
        if interface_class == LocationReferencesService:
            set_help_location(((LocationReferencesService) service).get_help_location())
            Swing.run_later(lambda: self.tool.remove_service_listener(self))
        else:
            return

    @property
    def help_location_service_listener(self):
        return ServiceListener(
            removed=self.help_location_service_removed,
            added=self.help_location_service_added)

    def is_enabled_for_context(self, context):
        location_references_service = self.tool.get_service(LocationReferencesService)
        if location_references_service is None:
            return False

        selection_paths = context.get_selected_symbol_tree_paths()
        if len(selection_paths) != 1:
            return False

        last_component_path = selection_paths[0].get_last_component_path()
        if isinstance(last_component_path, (CodeSymbolNode, FunctionSymbolNode, LibrarySymbolNode,
                                             LocalVariableSymbolNode, ParameterSymbolNode)):
            return True
        # TODO multi reference type
        # ClassSymbolNode  - maybe could be both when classes are real things in Ghidra
        # NamespaceSymbolNode
        # FunctionSymbolNode  - could be both

    def action_performed(self, context):
        location_references_service = self.tool.get_service(LocationReferencesService)
        code_viewer_service = self.tool.get_service(CodeViewerService)
        navigatable = code_viewer_service.get_navigatable()

        selection_paths = context.get_selected_symbol_tree_paths()
        symbol_node = selection_paths[0].get_last_component_path()
        program_location = self.get_program_location(symbol_node)
        if program_location is None:
            Msg.debug(self, f"Do not know how to show references to SymbolNode type: {symbol_node}")
            return

        location_references_service.show_references_to_location(program_location, navigatable)

    def get_program_location(self, symbol_node):
        symbol = symbol_node.get_symbol()
        if isinstance(symbol, FunctionSymbol):
            return FunctionSignatureFieldLocation(symbol.get_program(), symbol.get_address())
        else:
            return symbol.get_program_location()

```

Please note that Python does not have direct equivalent of Java's Swing and docking.