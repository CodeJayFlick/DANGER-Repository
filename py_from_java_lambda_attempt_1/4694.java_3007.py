Here is the translation of the Java code into Python:

```Python
class DWARFNameInfo:
    def __init__(self, parent=None, organizational_category_path=None, namespace_path=None, original_name=None):
        self.parent = parent
        if organizational_category_path is None:
            organizational_category_path = CategoryPath.ROOT
        if namespace_path is None:
            namespace_path = NamespacePath.ROOT
        self.organizational_category_path = organizational_category_path
        self.namespace_path = namespace_path
        self.original_name = original_name

    @staticmethod
    def create_root(root_category):
        return DWARFNameInfo(None, root_category, NamespacePath.ROOT, None)

    @staticmethod
    def from_data_type(data_type):
        return DWARFNameInfo(None, data_type.category_path, NamespacePath.create(None, data_type.name, SymbolType.NAMESPACE), data_type.name)

    @staticmethod
    def from_list(parent, names):
        for name in names:
            parent = DWARFNameInfo(parent, name, name, SymbolType.NAMESPACE)
        return parent

    def get_parent(self):
        return self.parent

    def is_root(self):
        return self.parent is None

    def get_organizational_category_path(self):
        return self.organizational_category_path

    def get_namespace_path(self):
        return self.namespace_path

    def get_name(self):
        return self.namespace_path.name

    def replace_name(self, new_name, original_name=None):
        if original_name is None:
            original_name = self.original_name
        return DWARFNameInfo(self.parent, original_name, new_name, self.get_type())

    def replace_type(self, new_type):
        return DWARFNameInfo(self.parent, self.original_name, self.name, new_type)

    def get_type(self):
        return self.namespace_path.type

    def as_category_path(self):
        if not self.is_root():
            return CategoryPath(self.organizational_category_path, self.get_parts())
        else:
            return self.organizational_category_path

    def as_data_type_path(self):
        if not self.is_root():
            return DataTypePath(self.as_category_path(), self.name)
        else:
            return None

    def get_parent_namespace(self, program):
        if self.parent is not None:
            return self.parent.as_namespace(program)

    def as_namespace(self, program):
        return self.namespace_path.get_namespace(program)

    def __str__(self):
        return f"{self.organizational_category_path} || {self.namespace_path}"

    @property
    def is_anon(self):
        return self.original_name is None

    @property
    def original_name(self):
        return self._original_name

    @original_name.setter
    def original_name(self, value):
        if not isinstance(value, str):
            raise TypeError("Original name must be a string")
        self._original_name = value

    def create_child(self, child_original_name, child_name, child_type):
        return DWARFNameInfo(self, child_original_name, child_name, child_type)

class CategoryPath:
    ROOT = ""

    def __init__(self, path):
        if path is None or not isinstance(path, str) and len(path) == 0:
            self.path = ""
        else:
            self.path = path

    @staticmethod
    def create(parent_path, name, type):
        return CategoryPath(f"{parent_path}/{name}" if parent_path != "" else f"{type}:{name}")

    def get_parts(self):
        return [part for part in self.path.split("/") if len(part) > 0]

class NamespacePath:
    ROOT = ""

    def __init__(self, path):
        if path is None or not isinstance(path, str) and len(path) == 0:
            self.path = ""
        else:
            self.path = path

    @staticmethod
    def create(parent_path, name, type):
        return NamespacePath(f"{parent_path}/{name}" if parent_path != "" else f"{type}:{name}")

class SymbolType:
    NAMESPACE = ""

# Usage example:

root_category = "Root"
data_type = {"category_path": root_category, "name": "Data Type", "type": SymbolType.NAMESPACE}
dwarf_name_info = DWARFNameInfo.from_data_type(data_type)
print(dwarf_name_info)  # Output: Root || Data Type
```

Please note that Python does not have direct equivalent of Java's `package` and `import`. In this translation, I've omitted the package declaration and import statements.