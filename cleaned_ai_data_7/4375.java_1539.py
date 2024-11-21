class ImportsCategoryNode:
    def __init__(self, program):
        super().__init__("Imports Category", program)

    @property
    def icon(self):
        return self._icon

    @icon.setter
    def icon(self, expanded):
        if expanded:
            self._icon = "openFolderExternals.png"
        else:
            self._icon = "closedFolderExternals.png"

    @property
    def tooltip(self):
        return "Symbols for External libraries"

    def supports_symbol(self, symbol):
        return symbol.is_external()
