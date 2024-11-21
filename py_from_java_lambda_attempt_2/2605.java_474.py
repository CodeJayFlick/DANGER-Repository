Here is the translation of the Java interface `TraceSymbolView` to a Python class:

```python
from collections import Collection

class TraceSymbolView:
    def __init__(self):
        self.manager = None  # Initialize manager attribute

    def get_manager(self) -> 'TraceSymbolManager':
        return self.manager

    @property
    def size(self, include_dynamic_symbols: bool = False) -> int:
        if not hasattr(self, '_all'):
            self._load_all(include_dynamic_symbols)
        return len(getattr(self, '_all'))

    def _load_all(self, include_dynamic_symbols: bool):
        # Load all symbols into the instance variable
        pass

    @property
    def all(self) -> Collection['TraceSymbol']:
        if not hasattr(self, '_all'):
            self._load_all()
        return getattr(self, '_all')

    def get_children_named(self, name: str, parent: 'NamespaceSymbol') -> Collection[' TraceSymbol']:
        # Implement this method to retrieve children with the given name
        pass

    def get_children(self, parent: 'NamespaceSymbol') -> Collection['TraceSymbol']:
        # Implement this method to retrieve all children of a namespace symbol
        pass

    @property
    def globals_named(self) -> Collection[' TraceSymbol']:
        return self.get_children_named('global', self.manager.global_namespace)

    @property
    def globals(self) -> Collection['TraceSymbol']:
        return self.get_children(self.manager.global_namespace)

    def get_named(self, name: str) -> Collection[' TraceSymbol']:
        # Implement this method to retrieve symbols with the given name
        pass

    def get_with_matching_name(self, glob: str, case_sensitive: bool = False) -> Collection['TraceSymbol']:
        # Implement this method to retrieve symbols whose names match a glob pattern
        pass


class NamespaceSymbol:
    pass  # Define this class as needed for your application


class TraceSymbolManager:
    def __init__(self):
        self.global_namespace = None  # Initialize global namespace attribute

    @property
    def get_global_namespace(self) -> 'NamespaceSymbol':
        return self.global_namespace
```

Note that I've omitted the implementation of some methods, as they are specific to your application and require additional context. You'll need to fill in these implementations based on how you want `TraceSymbolView` to behave.