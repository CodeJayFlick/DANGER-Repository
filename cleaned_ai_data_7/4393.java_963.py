class SymbolTreeActionContext:
    def __init__(self, provider, program, tree, selection_paths):
        self.selection_paths = selection_paths
        super().__init__(provider, program, self.get_symbols(selection_paths), tree)

    @property
    def symbol_tree_provider(self):
        return self.component_provider

    @property
    def symbol_tree(self):
        return self.context_object

    @property
    def selected_symbol_tree_paths(self):
        return self.selection_paths

    def get_selected_path(self):
        if len(self.selection_paths) == 1:
            return self.selection_paths[0]
        else:
            return None

    @staticmethod
    def get_symbols(selection_paths):
        if selection_paths is None:
            return []
        
        symbols = []
        for tree_path in selection_paths:
            object_ = tree_path.get_last_component()
            if isinstance(object_, SymbolNode):
                symbol_node = object_
                symbols.append(symbol_node.symbol)
            else:
                # Do not return symbols if selection contains non-symbolNodes
                return []

        return symbols

class TreePath:
    def get_last_component(self):
        pass  # This is a placeholder, the actual implementation would depend on your specific use case.

class SymbolNode:
    @property
    def symbol(self):
        pass  # This is a placeholder, the actual implementation would depend on your specific use case.
