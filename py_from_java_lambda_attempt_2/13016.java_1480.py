Here is the translation of the Java code to Python:
```python
import os
from collections import defaultdict

class JarEntryNode:
    def __init__(self, parent=None, name=""):
        self.parent = parent
        self.name = name
        self.child_map = None if not hasattr(self, 'child_map') else getattr(self, 'child_map')

    @property
    def child_map(self):
        return defaultdict(dict) if self.child_map is None else self.child_map

    def get_node(self, child_name):
        if self.child_map is None:
            return None
        if child_name == ".":
            return self
        if child_name == "..":
            return self.parent
        return self.child_map.get(child_name)

    def create_node(self, child_name):
        node = self.get_node(child_name)
        if node is None:
            node = JarEntryNode(parent=self, name=child_name)
            if self.child_map is None:
                self.child_map = defaultdict(dict)
            self.child_map[child_name] = node
        return node

    def get_path(self):
        if self.parent is None:
            return ""
        parent_path = self.parent.get_path()
        return f"{parent_path}/{self.name}" if len(parent_path) > 0 else self.name

    @property
    def path(self):
        return self.get_path()

    def get_children(self):
        if self.child_map is None:
            return []
        return list(self.child_map.values())

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def __getattr__(self, attr):
        if attr == "get_children":
            return lambda: [child for child in self.child_map.values()]
        raise AttributeError(f"Object of type {type(self)} has no attribute '{attr}'")

    @property
    def is_directory(self):
        return bool(self.child_map)

    @property
    def is_file(self):
        return not self.is_directory

    def get_input_stream(self) -> bytes:
        jar_file = self.get_jar_file()
        if jar_file is None:
            raise ValueError("Jar file not found")
        entry = jar_file.get_entry(self.path)
        if entry is None:
            raise FileNotFoundError(f"Entry '{self.path}' not found in jar file")
        return jar_file.read(entry)

    def get_jar_file(self):
        return self.parent.get_jar_file() if hasattr(self, 'parent') else None

    @property
    def parent(self):
        return getattr(self, '_parent', None) or None

    @parent.setter
    def parent(self, value):
        self._parent = value

    def get_node_by_path(self, path: list[str]) -> "JarEntryNode":
        node = self
        for child_name in path:
            if (node := node.get_node(child_name)) is None:
                return None
        return node

    @property
    def last_modified(self):
        jar_file = self.get_jar_file()
        entry = jar_file.get_entry(self.path)
        return entry.timestamp if entry else 0

    @property
    def length(self) -> int:
        jar_file = self.get_jar_file()
        entry = jar_file.get_entry(self.path)
        return entry.size if entry else -1
```
Note that I've used the `defaultdict` from the `collections` module to implement the child map, and also added some Python-specific features like property decorators (`@property`) and a custom `__getattr__` method. Additionally, I've replaced the Java-style getter/setter methods with Python's built-in attribute access syntax (e.g., `self.name = value`).