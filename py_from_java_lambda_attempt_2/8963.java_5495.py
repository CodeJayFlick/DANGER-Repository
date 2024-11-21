Here is the translation of the Java interface `FunctionAssociationContext` to a Python class:

```python
class FunctionAssociationContext:
    def get_selected_source_function(self):
        # Implement this method in your subclass
        pass

    def get_selection_destination_function(self):
        # Implement this method in your subclass
        pass

    def get_existing_match(self):
        # Implement this method in your subclass
        return None  # Default value if no match exists

    def can_create_match(self):
        # Implement this method in your subclass
        return False  # Default value, assume a new match cannot be created
```

Note that I've used Python's convention for naming methods (e.g., `get_selected_source_function` instead of `getSelectedSourceFunction`). Additionally, since the Java interface is abstract and doesn't provide any implementation, I've left the method bodies empty in this translation. You would need to implement these methods in a subclass or concrete class that inherits from `FunctionAssociationContext`.