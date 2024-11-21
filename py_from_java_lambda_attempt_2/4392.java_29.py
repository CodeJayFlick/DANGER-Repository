Here is the translation of the Java code into Python:

```Python
class SymbolGTreeDragNDropHandler:
    def __init__(self, plugin):
        self.plugin = plugin

    def drop(self, destination_node, transferable, drop_action):
        if drop_action != 2:  # DnDConstants. ACTION_MOVE
            return
        
        if not isinstance(destination_node, SymbolTreeNode):
            return
        
        namespace = destination_node.get_namespace()
        if namespace is None:
            return

        try:
            data = transferable.get_data(SymbolTreeDataFlavor.DATA_FLAVOR)
            self.drop_symbol_tree(namespace, data)
        except (UnsupportedFlavorException, IOException) as e:
            Msg.show_error(self, "Unexpected Exception", str(e))

    def drop_program_selection(self, namespace, selection_data):
        symbols_to_move = []
        program = self.plugin.get_program()
        function_manager = program.get_function_manager()
        address_set = selection_data.get_address_set()
        iterator = function_manager.get_functions(address_set, True)
        for func in iterator:
            symbol = func.get_symbol()
            symbols_to_move.append(symbol)

        provider = self.plugin.get_provider()
        if len(symbols_to_move) != provider.reparent_symbols(namespace, symbols_to_move):
            self.plugin.get_tool().set_status_info("Failed to move one more specified symbols")

    def drop_node_list(self, namespace, transfer_data):
        node_list = list(transfer_data)
        symbols_to_move = []
        for node in node_list:
            if isinstance(node, SymbolNode):
                symbol = node.get_symbol()
                symbols_to_move.append(symbol)

        provider = self.plugin.get_provider()
        if len(symbols_to_move) != provider.reparent_symbols(namespace, symbols_to_move):
            self.plugin.get_tool().set_status_info("Failed to move one more specified symbols")

    def get_supported_drag_actions(self):
        return 2  # DnDConstants. ACTION_MOVE

    def is_drop_site_ok(self, destination_user_node, flavors, drop_action):
        if drop_action != 2:  # DnDConstants. ACTION_MOVE
            return False
        
        program = self.plugin.get_program()
        if program is None or program.is_closed():
            return False
        
        if not isinstance(destination_user_node, SymbolTreeNode):
            return False

        node = destination_user_node
        return node.supports_data_flavors(flavors)

    def is_start_drag_ok(self, drag_userdata, drop_action):
        if drop_action != 2:  # DnDConstants. ACTION_MOVE
            return False
        
        for node in drag_userdata:
            symbol_node = node
            data_flavor = symbol_node.get_node_data_flavor()
            if data_flavor is None:
                return False

        return len(drag_userdata) > 0

    def get_supported_data_flavors(self, transfer_nodes):
        flavor_set = set()
        for node in transfer_nodes:
            symbol_node = node
            flavor = symbol_node.get_node_data_flavor()
            if flavor is not None:
                flavor_set.add(flavor)

        return list(flavor_set)

    def get_transfer_data(self, transfer_nodes, flavor):
        raise UnsupportedFlavorException("Unsupported Flavor")

class SymbolTreeNode:
    pass

class Msg:
    @staticmethod
    def show_error(instance, title, message):
        print(f"Error: {title} - {message}")

    @staticmethod
    def show_info(instance, title, message):
        print(f"{title}: {message}")
```

Note that I've used Python's built-in `set` and `list` types to represent the Java code's use of `HashSet` and `ArrayList`.