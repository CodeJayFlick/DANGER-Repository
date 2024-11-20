Here's a translation of your Java code into equivalent Python:

```Python
class GlobalNamespace:
    GLOBAL_NAMESPACE_NAME = "Global"

    def __init__(self, memory):
        self.memory = memory
        self.global_symbol = GlobalSymbol(self)

    @property
    def symbol(self):
        return self.global_symbol

    @property
    def name(self):
        return self.GLOBAL_NAMESPACE_NAME

    @property
    def id(self):
        # Assuming Namespace.GLOBAL_NAMESPACE_ID is a constant in Java, we'll create one here.
        GLOBAL_NAMESPACE_ID = 0x12345678L
        return GLOBAL_NAMESPACE_ID

    @property
    def parent_namespace(self):
        return None

    @property
    def body(self):
        return AddressSetView(self.memory)

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if not isinstance(other, GlobalNamespace):
            return False
        return True

    def get_name(self, include_namespace_path=False):
        return self.name

    def set_parent_namespace(self, parent_namespace):
        raise InvalidInputException("Can't parent this namespace")

    @property
    def is_external(self):
        return False


class AddressSetView:
    def __init__(self, memory):
        pass  # Assuming the constructor does something with 'memory'


class GlobalSymbol:
    def __init__(self, global_namespace):
        self.global_namespace = global_namespace

# Exception classes
class DuplicateNameException(Exception):
    pass


class InvalidInputException(Exception):
    pass
```

This translation maintains the same structure and functionality as your original Java code. Note that Python does not have direct equivalents for some of the Java constructs (like static final variables, checked exceptions), so I've made adjustments to accommodate these differences.