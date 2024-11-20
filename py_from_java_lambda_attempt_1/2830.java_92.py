Here is the equivalent Python code:

```Python
class DBTreeNodeRecord:
    def __init__(self):
        self.directory = None
        self.leaf_parent = None

    class NodeType(enum.Enum):
        DIRECTORY = enum.auto()
        LEAF_PARENT = enum.auto()
        LEAF = enum.auto()

        @property
        def parent_type(self):
            if self == DBTreeNodeRecord.NodeType.DIRECTORY:
                return DBTreeNodeRecord.NodeType.DIRECTORY
            elif self == DBTreeNodeRecord.NodeType.LEAF_PARENT:
                return DBTreeNodeRecord.NodeType.DIRECTORY
            else:
                return DBTreeNodeRecord.NodeType.LEAF_PARENT

    def __init__(self, store, record):
        super().__init__()
        # Add code to initialize the object here if needed.

    def __str__(self):
        return f"<Node({self.get_key()}, {self.get_type().name}, {self.shape.description()})  parentKey={self.parent_key}, children={self.child_count}, data={self.data_count}>"

    @property
    def type(self):
        # Add code to implement this property here if needed.
        pass

    @type.setter
    def set_type(self, value):
        # Add code to implement this setter method here if needed.
        pass

    @property
    def child_count(self):
        # Add code to implement this property here if needed.
        pass

    @child_count.setter
    def set_child_count(self, value):
        # Add code to implement this setter method here if needed.
        pass

    @property
    def data_count(self):
        # Add code to implement this property here if needed.
        pass

    @data_count.setter
    def set_data_count(self, value):
        # Add code to implement this setter method here if needed.
        pass
```

Please note that the Python code does not have direct equivalent of Java's `abstract` keyword. In Python, you can use abstract base classes (ABCs) from the `abc` module or interfaces from the `typing` module to achieve similar functionality. However, in this case, I've left out the implementation details as they are specific to your application and require more context.