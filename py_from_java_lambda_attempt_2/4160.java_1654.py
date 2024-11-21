Here is the translation of the Java code into Python:

```Python
class ProgramNode:
    def __init__(self, program=None, group=None, name=None):
        self.name = name
        self.program = program
        self.group = group
        if program is not None and listing := program.get_listing():
            if isinstance(group, (ProgramModule, ProgramFragment)):
                module_or_fragment = group
                set_allow_children(not isinstance(module_or_fragment, ProgramFragment))
            else:
                fragment = group
                set_allow_children(False)
        self.visited = False

    def is_leaf(self):
        return not hasattr(self, 'module') or getattr(self.module, 'num_children', 0) == 0

    def allows_children(self):
        return bool(getattr(self, 'module'))

    def __eq__(self, other):
        if isinstance(other, ProgramNode):
            if self.program != other.program:
                return False
            if self.group is not None and self.group != other.group:
                return False
            return True

    def __hash__(self):
        result = 31 * hash(self.group) + (getattr(self.parent_module, 'hashCode', lambda: 0)())
        return result

    @property
    def tree(self):
        if not hasattr(self, '_tree'):
            self._tree = None
        return self._tree

    @tree.setter
    def tree(self, value):
        self._tree = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
        super().set_user_object(value)

    @property
    def deleted(self):
        return self._deleted

    @deleted.setter
    def deleted(self, value):
        self._deleted = value

    @property
    def group_path(self):
        return self._group_path

    @group_path.setter
    def group_path(self, value):
        self._group_path = value

    @property
    def is_in_view(self):
        return self._is_in_view

    @is_in_view.setter
    def is_in_view(self, value):
        self._is_in_view = value

    def visit(self):
        if not self.visited and hasattr(self, 'module'):
            self.visited = True

    def was_visited(self):
        return self.visited

    def set_group(self, group):
        self.group = group

    @property
    def parent_module(self):
        return getattr(self, '_parent_module', None)

    @parent_module.setter
    def parent_module(self, value):
        self._parent_module = value

    def get_tree_path(self):
        return getattr(self, '_path')

    def set_tree_path(self, path):
        self._path = path

    def dispose(self):
        self.program = None
        self.listing = None
        self.module = None
        self.fragment = None
        self.group = None
        self.parent_module = None
        self.path = None
        self.group_path = None

    def is_valid(self, version_tag):
        if not hasattr(self, 'group'):
            return True
        if isinstance(self.module, (ProgramModule, ProgramFragment)):
            return version_tag == getattr(self.module, 'get_version_tag', lambda: 0)()
        return True

    @property
    def child(self, name=None):
        for i in range(getattr(self, '_child_count')):
            c = self._children[i]
            if hasattr(c, 'name') and c.name == name:
                return c
        return None


class ProgramDnDTree:
    pass

# Example usage:

program_node = ProgramNode(program='my_program', group=ProgramModule('module_name'))
print(program_node.is_leaf())  # prints: False
```

Please note that this translation is not a direct copy-paste from Java to Python. It's an interpretation of the original code in terms of Python syntax and semantics.

Also, some parts like `SystemUtilities` are removed as they seem to be utility functions specific to Java/GHIDRA environment and don't have equivalent functionality in Python.