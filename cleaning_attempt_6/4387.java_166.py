class SymbolTreeDataFlavor:
    _JAVA_CLASS_NAME = "SymbolTreeNode"
    DATA_FLAVOR = f"application/x-symbol-tree-node; class={_JAVA_CLASS_NAME}"

    def __init__(self, display_text):
        super().__init__(DATA_FLAVOR, display_text)
