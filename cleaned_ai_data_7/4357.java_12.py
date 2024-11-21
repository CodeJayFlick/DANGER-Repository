class GoToExternalLocationAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Go To External Location", plugin.name)

    @property
    def popup_menu_data(self):
        return MenuData(["Go to External Location"], "images/searchm_obj.gif", "0External")

    def is_enabled_for_context(self, context):
        if len(context.symbols) != 1:
            return False

        symbol = next(iter(context.symbols), None)
        if symbol is None or (symbol.symbol_type in [SymbolType.LABEL, SymbolType.FUNCTION] and not symbol.is_external()):
            return False
        return True

    def perform_action(self, context):
        symbol = next(iter(context.symbols), None)
        if symbol is None:
            return  # assume symbol removed

        obj = symbol.object
        ext_loc = None
        if isinstance(obj, Function) and obj.is_external():
            ext_loc = obj.external_location
        elif isinstance(obj, ExternalLocation):
            ext_loc = obj

        if ext_loc is not None:
            self.plugin.go_to(ext_loc)
