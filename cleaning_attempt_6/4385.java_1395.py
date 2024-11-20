class SymbolCategoryNode:
    MAX_NODES_BEFORE_ORGANIZING = 40
    MAX_NODES_BEFORE_CLOSING = 200

    def __init__(self):
        self.symbol_category = None
        self.symbol_table = None
        self.global_namespace = None
        self.program = None

    def __init__(self, symbol_category: SymbolCategory, program: Program):
        this.symbol_category = symbol_category
        this.program = program
        this.symbol_table = program.get_symbol_table()
        this.global_namespace = program.get_global_namespace()

    @staticmethod
    def generate_children(monitor) -> List[GTreeNode]:
        if not isinstance(monitor, TaskMonitorAdapter):
            raise TypeError("monitor must be a TaskMonitorAdapter")

        symbol_type = self.symbol_category.get_symbol_type()
        list_ = get_symbols(symbol_type, monitor)
        return organization_node.organize(list_, MAX_NODES_BEFORE_ORGANIZING)

    def get_program(self) -> Program:
        return self.program

    @staticmethod
    def get_symbols(type: SymbolType, global_only=False, monitor=None):
        if not isinstance(monitor, TaskMonitorAdapter):
            raise TypeError("monitor must be a TaskMonitorAdapter")

        list_ = []
        symbol_type = self.symbol_category.get_symbol_type()
        monitor.initialize(self.symbol_table.num_symbols)
        it = (
            self.symbol_table.symbols(global_namespace) 
            if global_only else
            self.symbol_table.symbol_iterator()
        )
        while it.has_next():
            s = it.next()
            monitor.increment_progress(1)
            monitor.check_canceled()
            if s and (s.get_symbol_type() == symbol_type):
                list_.append(SymbolNode.create_node(s, program))
        return sorted(list_, key=self.children_comparator)

    def can_cut(self) -> bool:
        return False

    @staticmethod
    def is_modifiable():
        return False

    def set_node_cut(self, cut: bool):
        raise NotImplementedError("Cannot cut a Category node")

    def get_symbol_category(self) -> SymbolCategory:
        return self.symbol_category

    def __str__(self) -> str:
        return f"SymbolCategoryNode({self.symbol_category.name})"

    @staticmethod
    def is_local_data_flavor(flavor: DataFlavor):
        if flavor == CodeSymbolNode.LOCAL_DATA_FLAVOR or \
           flavor == FunctionSymbolNode.LOCAL_DATA_FLAVOR or \
           flavor == NamespaceSymbolNode.LOCAL_DATA_FLAVOR or \
           flavor == ClassSymbolNode.LOCAL_DATA_FLAVOR:
            return True
        else:
            return False

    def symbol_added(self, symbol: Symbol) -> SymbolNode:
        if not self.is_loaded():
            return None

        if not supports_symbol(symbol):
            return None

        parent_node = this
        if symbol.global_:
            return do_add_symbol(symbol, parent_node)
        else:
            namespace_symbol = symbol.parent_namespace.get_symbol()
            key = SymbolNode.create_key_node(namespace_symbol, program)
            parent_node = find_symbol_tree_node(key, False, TaskMonitorAdapter.DUMMY_MONITOR)
            if parent_node is None:
                return None
            return do_add_symbol(symbol, parent_node)

    @staticmethod
    def do_add_symbol(symbol: Symbol, node: GTreeNode):
        new_node = SymbolNode.create_node(symbol, program)
        add_node(node, new_node)
        return new_node

    @staticmethod
    def do_remove_node(parent: GTreeNode, child: GTreeNode):
        parent.remove_child(child)

    def symbol_removed(self, symbol: Symbol, old_name: str, monitor=None) -> None:
        if not self.is_loaded():
            return

        key = SymbolNode.create_key_node(symbol, old_name, program)
        node = find_symbol_tree_node(key, False, monitor)
        if node is None:
            return
        parent = node.parent
        parent.remove_child(node)

    @staticmethod
    def supports_symbol(symbol: Symbol) -> bool:
        if not symbol.global_ or symbol.external:
            return False
        type = symbol.get_symbol_type()
        return type == self.symbol_category.get_symbol_type()

class TaskMonitorAdapter:
    DUMMY_MONITOR = None

# Other classes and methods are omitted for brevity.
