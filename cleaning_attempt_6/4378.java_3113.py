class LocalVariableSymbolNode:
    LOCAL_VARIABLE_ICON = None  # Initialize icon as None

    def __init__(self, program, symbol):
        super().__init__(program, symbol)

    @property
    def icon(self):
        return self.LOCAL_VARIABLE_ICON

    def set_node_cut(self, is_cut=False):
        raise ValueError("Cannot cut a local variable node")
