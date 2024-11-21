Here is the translation of the Java interface `DebugHostSymbols` into a Python class:

```python
class DebugHostSymbols:
    def create_module_signature(self, module_name: str, min_version: str, max_version: str) -> dict:
        # Implement this method in your subclass
        pass

    def create_type_signature(self, signature_specification: str, module: 'DebugHostModule') -> dict:
        # Implement this method in your subclass
        pass

    def create_type_signature_for_module_range(
            self,
            signature_specification: str,
            module_name: str,
            min_version: str,
            max_version: str) -> dict:
        # Implement this method in your subclass
        pass

    def enumerate_modules(self, context: 'DebugHostContext') -> list:
        # Implement this method in your subclass
        pass

    def find_module_by_name(self, context: 'DebugHostContext', module_name: str) -> 'DebugHostModule':
        # Implement this method in your subclass
        pass

    def find_module_by_location(self, context: 'DebugHostContext', location: dict) -> 'DebugHostModule':
        # Implement this method in your subclass
        pass

    def get_most_derived_object(
            self,
            context: 'DebugHostContext',
            location: dict,
            object_type: 'DebugHostType') -> 'DebugHostType':
        # Implement this method in your subclass
        pass


class DebugHostModule:
    pass


class DebugHostType:
    pass


class DebugHostContext:
    pass
```

Note that I've used the `pass` statement to indicate where you would need to implement each method. You will also need to define the classes `DebugHostModule`, `DebugHostType`, and `DebugHostContext`.