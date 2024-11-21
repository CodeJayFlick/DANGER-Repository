Here is the translation of the Java code into Python:

```Python
class SymbolTreeNode:
    SYMBOL_COMPARATOR = lambda s1, s2: (None if s1 is None else 0) - (None if s2 is None else 0)
    
    def __init__(self):
        pass

    def can_cut(self):
        raise NotImplementedError("can_cut must be implemented by subclass")

    def can_paste(self, pasted_nodes):
        raise NotImplementedError("can_paste must be implemented by subclass")

    def set_node_cut(self, is_cut):
        raise NotImplementedError("set_node_cut must be implemented by subclass")

    def is_cut(self):
        raise NotImplementedError("is_cut must be implemented by subclass")

    def get_node_data_flavor(self):
        raise NotImplementedError("get_node_data_flavor must be implemented by subclass")

    def supports_data_flavors(self, data_flavors):
        raise NotImplementedError("supports_data_flavors must be implemented by subclass")

    def get_namespace(self):
        raise NotImplementedError("get_namespace must be implemented by subclass")

    def get_children_comparator(self):
        return self.SYMBOL_COMPARATOR

    def get_symbol(self):
        return None  # stub method, to be overridden in subclasses

    def find_symbol_tree_node(self, key, load_children, monitor=None):
        if not load_children and not self.is_loaded():
            return None
        
        children = self.get_children()
        try:
            index = bisect.bisect_left(children, key)
        except ValueError:
            index = -1
        if 0 <= index < len(children) and children[index].get_symbol() == key.get_symbol():
            return children[index]
        
        for child_node in children:
            if monitor is not None and monitor.is_cancelled():
                return None
            if isinstance(child_node, SymbolTreeNode):
                found_node = child_node.find_symbol_tree_node(key, load_children, monitor)
                if found_node is not None:
                    return found_node
        
        return None

class GTreeSlowLoadingNode:
    pass  # stub class for now
```

Note that I've used Python's `lambda` function to define the comparator. Also, some methods in Java are abstract and need to be implemented by subclasses, so I've left those as `raise NotImplementedError("... must be implemented by subclass")`.