class RemoveLabelAction:
    def __init__(self, plugin):
        self.plugin = plugin
        super().__init__("Remove Label", plugin.name)

    @property
    def popup_path(self):
        return ["Remove Label"]

    @property
    def keybinding(self):
        # Note: In Python, we don't have a direct equivalent of Java's KeyStroke class.
        # We can use the built-in `keyboard` module to achieve similar functionality,
        # but for simplicity, let's just hardcode the VK_DELETE value here:
        return "DELETE"

    def set_enabled(self):
        self.enabled = True

    @property
    def enabled(self):
        return self._enabled

    @enabled.setter
    def enabled(self, value):
        self._enabled = value

    def actionPerformed(self, context):
        self.plugin.remove_label_callback(context)

    def is_enabled_for_context(self, context):
        if not self.plugin.is_on_external_reference(context) and self.on_symbol(context):
            return True
        else:
            return False

    def on_symbol(self, context):
        symbol = self.plugin.get_symbol(context)
        if isinstance(symbol, (CodeSymbol, FunctionSymbol)):
            if isinstance(symbol, CodeSymbol) and not symbol.is_dynamic():
                return True
            elif isinstance(symbol, FunctionSymbol) and symbol.source != SourceType.DEFAULT:
                return True
        return False

    def dispose(self):
        super().dispose()
        self.plugin = None


class LabelMgrPlugin:
    pass  # We don't have enough information to implement this class in Python.
