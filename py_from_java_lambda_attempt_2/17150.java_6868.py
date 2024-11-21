Here is the translation of the given Java code into Python:

```Python
class InternalMNode:
    def __init__(self, parent=None, name=''):
        self.children = None  # ConcurrentHashMap instance
        self.schema_template = None
        super().__init__(parent, name)

    @property
    def children(self):
        return self._children

    @children.setter
    def children(self, value):
        if not isinstance(value, dict):
            raise TypeError('Children must be a dictionary')
        self._children = value

    def has_child(self, name: str) -> bool:
        return self.children is not None and name in self.children

    def get_child(self, name: str) -> 'InternalMNode':
        if self.children is None:
            return None
        return self.children.get(name)

    def add_child(self, name: str, child: 'InternalMNode') -> None:
        if self.children is None:
            with lock(self):
                if self.children is None:
                    self.children = {}
        child.parent = self
        self.children[name] = child

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, value):
        self._parent = value

    def delete_child(self, name: str) -> None:
        if self.children is not None and name in self.children:
            del self.children[name]

    def replace_child(self, old_name: str, new_child: 'InternalMNode') -> None:
        child_node = self.get_child(old_name)
        if child_node is None or not isinstance(child_node, InternalMNode):
            return
        grand_children = child_node.children.copy()
        for name, node in grand_children.items():
            node.parent = new_child
        new_child.children.update(grand_children)

    def get_upper_template(self) -> 'Template':
        cur = self
        while cur is not None:
            if cur.schema_template is not None:
                return cur.schema_template
            cur = cur.parent

        return None

    @property
    def schema_template(self):
        return self._schema_template

    @schema_template.setter
    def schema_template(self, value: 'Template'):
        self._schema_template = value

    def serialize_to(self, log_writer) -> None:
        if self.children is not None:
            for child in self.children.values():
                child.serialize_to(log_writer)
        log_writer.serialize_mnode(self)

def deserialize_from(plan):
    return InternalMNode(None, plan.name)
```

Note: Python does not have direct equivalent of Java's `Map` and `ConcurrentHashMap`. Instead, we use built-in dictionary type which is thread-safe. Also, the concept of volatile variable in Java doesn't exist directly in Python as it has its own way to handle multi-threading issues using locks or atomic operations.