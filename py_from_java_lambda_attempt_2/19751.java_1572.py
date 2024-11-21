Here is a translation of the Java code into equivalent Python:

```Python
class ExprAllGroups:
    def __init__(self):
        pass

    @staticmethod
    def register_expression():
        return {"all groups": (str, "simple", None)}

    def init(self, exprs=None, matched_pattern=0, is_delayed=False, parse_result=None):
        if not VaultHook().has_group_support():
            Skript.error(VaultHook.NO_GROUP_SUPPORT)
            return False
        return True

    @staticmethod
    @property
    def get_groups(vault_hook: VaultHook) -> list:
        return vault_hook.permission.get_groups()

    def get_return_type(self):
        return str

    def is_single(self):
        return False

    def __str__(self, e=None, debug=False):
        if not isinstance(e, type(None)):
            raise TypeError("Event should be None")
        return "all groups"
```

Please note that Python does not support static methods or properties like Java. Also, the `@Override` annotation is used in Java to indicate that a method overrides one from its superclass; this concept doesn't exist in Python.

This code defines an `ExprAllGroups` class with several methods:

- The constructor (`__init__`) takes no arguments.
- The `register_expression` method returns a dictionary describing the expression, including its name and return type.
- The `init` method checks if Vault has group support; if not, it raises an error. Otherwise, it returns True.
- The `get_groups` property (which is essentially a static method) retrieves groups from Vault's permission system.
- The `get_return_type` method simply returns the string class type.
- The `is_single` method always returns False.
- The `__str__` method converts an event to its string representation.