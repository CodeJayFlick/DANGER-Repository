from abc import ABCMeta, abstractmethod

class GTreeNode(metaclass=ABCMeta):
    def __init__(self):
        self.children = []

    @abstractmethod
    def get_name(self) -> str:
        pass

    @abstractmethod
    def get_icon(self, expanded: bool) -> object:
        pass

    @abstractmethod
    def get_tooltip(self) -> str:
        pass

    @abstractmethod
    def is_leaf(self) -> bool:
        pass

    def add_node(self, node):
        Swing.run_now(lambda: self.do_add_node(node))

    def add_nodes(self, nodes):
        Swing.run_now(lambda: self.do_add_nodes(nodes))

    def add_node_at_index(self, index: int, node):
        Swing.run_now(lambda: self.do_add_node_at_index(index, node))

    @abstractmethod
    def generate_children(self) -> list:
        pass

    def get_display_text(self) -> str:
        return self.get_name()

    def get_children(self) -> list:
        return self.children.copy()

    def get_child_count(self) -> int:
        return len(self.children)

    def get_child_at_index(self, index: int) -> object:
        if 0 <= index < len(self.children):
            return self.children[index]
        else:
            return None

    @abstractmethod
    def is_editable(self) -> bool:
        pass

    @abstractmethod
    def value_changed(self, new_value: object) -> None:
        pass

    def get_root(self) -> 'GTreeNode':
        if not hasattr(self, '_root'):
            self._set_root()
        return self._root

    def _set_root(self):
        parent = self.get_parent()
        while isinstance(parent, GTreeRootParentNode):
            parent = parent.get_parent()
        self._root = parent

    @abstractmethod
    def get_tree_path(self) -> list:
        pass

    def fire_node_structure_changed(self, node: 'GTreeNode'):
        Swing.run_now(lambda: self.do_fire_node_structure_changed())

    def fire_node_changed(self, parent: 'GTreeNode', node: 'GTreeNode'):
        Swing.run_now(lambda: self.do_fire_node_changed(parent, node))

    @abstractmethod
    def get_name(self) -> str:
        pass

    def expand(self):
        tree = self.get_tree()
        if tree is not None:
            tree.expand_path(self)

    def collapse(self):
        tree = self.get_tree()
        if tree is not None:
            tree.collapse_all(self)

    @abstractmethod
    def get_icon_expanded(self) -> object:
        pass

    @abstractmethod
    def get_tooltip_text(self) -> str:
        pass

    def is_expanded(self) -> bool:
        tree = self.get_tree()
        if tree is not None:
            return tree.is_expanded(self.get_tree_path())
        else:
            return False

class GTreeRootParentNode(GTreeNode):
    @abstractmethod
    def get_parent(self) -> 'GTreeNode':
        pass

def Swing(func: callable):
    # implement your own swing functionality here
    func()

def CollectionUtils():
    # implement your own collection utilities here
    pass

# You can use the following code as a template for implementing abstract methods in subclasses:
class MyNode(GTreeNode):
    def get_name(self) -> str:
        return "My Node"

    def generate_children(self) -> list:
        return []

    def is_editable(self) -> bool:
        return True

    # and so on...
