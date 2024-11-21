class FunctionCategoryNode:
    OPEN_FOLDERS_FUNCTIONS_ICON = None
    CLOSED_FOLDERS_FUNCTIONS_ICON = None

    def __init__(self, program):
        super().__init__(SymbolCategory.FUNCTION_CATEGORY, program)

    # This function will allow symbols to appear both in the 'Functions' node and 
    # in the namespaces node, if they have a namespace. We have decided that we only
    # want symbols appearing in one or the other node, as does the LabelCategoryNode.
    # Anywho, if you put this code back in, then you must change supportsSymbol() below
    # to know how to allow symbols to be both in this node and the namespaces node.

    def get_symbols(self, type, monitor):
        nodes = []
        for symbol in program.get_symbol_table().get_symbols(program.get_memory(), SymbolType.FUNCTION, True):
            if symbol is not None:
                nodes.append(SymbolNode.create_node(symbol, program))
        return nodes

    @property
    def icon(self):
        return self.OPEN_FOLDERS_FUNCTIONS_ICON if self.expanded else self.CLOSED_FOLDERS_FUNCTIONS_ICON

    @property
    def tooltip(self):
        return "Symbols for Functions"

    def supports_data_flavors(self, data_flavors):
        for flavor in data_flavors:
            if flavor == FunctionSymbolNode.LOCAL_DATA_FLAVOR:
                return True
        return False

    def can_paste(self, pasted_nodes):
        for node in pasted_nodes:
            if not isinstance(node, (FunctionCategoryNode, LabelCategoryNode)):
                return False
        return True

    @property
    def children_comparator(self):
        # this category node uses OrganizationNodes
        return OrganizationNode.COMPARATOR

    def symbol_added(self, symbol):
        if not self.is_loaded():
            return None
        
        if not self.supports_symbol(symbol):
            return None

        if is_variable_parameter_or_code_symbol(symbol) or is_child_namespace_of_function(symbol):
            return super().symbol_added(symbol)

        new_node = SymbolNode.create_node(symbol, program)
        do_add_node(self, new_node)
        return new_node

    def is_child_namespace_of_function(self, symbol):
        while True:
            if isinstance(symbol, Function):
                return False
            parent_namespace = symbol.get_parent_namespace()
            if parent_namespace == global_namespace:
                break
            symbol = parent_namespace
        return True

    def is_variable_parameter_or_code_symbol(self, symbol):
        symbol_type = symbol.get_symbol_type()
        return symbol_type in [SymbolType.LOCAL_VAR, SymbolType.PARAMETER, SymbolType.LABEL]

    @property
    def supports_symbol(self, symbol):
        if super().supports_symbol(symbol):
            return True

        parent_namespace = symbol.get_parent_namespace()
        while parent_namespace is not None and parent_namespace != global_namespace:
            if isinstance(parent_namespace, Function):
                return True
            parent_namespace = parent_namespace.get_parent_namespace()

    def find_symbol_tree_node(self, key, loadChildren, monitor):
        # Special Case: this node uses the OrganizationNode for partitioning child 
        #               nodes. Further, some functions may contain Label symbols whose name
        #               is not related to the function name.
        if not loadChildren and not self.is_loaded():
            return None

        node = maybe_search_for_symbol_inside_of_function(key, loadChildren, monitor)
        if node:
            return node
        
        return super().find_symbol_tree_node(key, loadChildren, monitor)

    def maybe_search_for_symbol_inside_of_function(self, key, loadChildren, monitor):
        symbol = key.get_symbol()
        parent_symbol = symbol.get_parent_symbol()
        if parent_symbol is None:
            return None

        parent_type = parent_symbol.get_symbol_type()
        if parent_type != SymbolType.FUNCTION:
            return None
        
        parent_key = SymbolNode.create_node(parent_symbol, program)
        node = super().find_symbol_tree_node(parent_key, loadChildren, monitor)
        if node is None:
            return None
        
        # At this point we have a function and we have found the node for that 
        # function. Search that node for the symbol.
        return (node).find_symbol_tree_node(key, loadChildren, monitor)

    def __init__(self):
        self.OPEN_FOLDERS_FUNCTIONS_ICON = ResourceManager.load_image("images/openFolderFunctions.png")
        self.CLOSED_FOLDERS_FUNCTIONS_ICON = ResourceManager.load_image("images/closedFolderFunctions.png")

class SymbolNode:
    @classmethod
    def create_node(cls, symbol, program):
        pass

class OrganizationNode:
    COMPARATOR = None

# This is not a part of the original code but I added it to make the Python version work.
ResourceManager = object()
global_namespace = object()

program = object()
