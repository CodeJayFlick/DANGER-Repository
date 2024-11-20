Here's the translation of the Java interface `DbgModuleMemory` into a Python class:

```python
class DbgModuleMemory:
    def get_name(self):
        pass  # Implement this method in your subclass

    def get_id(self):
        pass  # Implement this method in your subclass

    def get_vma_start(self):
        pass  # Implement this method in your subclass

    def get_vma_end(self):
        pass  # Implement this method in your subclass

    def get_type(self):
        pass  # Implement this method in your subclass

    def get_protect(self):
        return []  # Return an empty list, implement the actual logic in your subclass

    def get_allocation_protect(self):
        return []  # Return an empty list, implement the actual logic in your subclass

    def get_allocation_base(self):
        pass  # Implement this method in your subclass

    def get_state(self):
        pass  # Implement this method in your subclass

    def is_read(self):
        pass  # Implement this method in your subclass

    def is_write(self):
        pass  # Implement this method in your subclass

    def is_exec(self):
        pass  # Implement this method in your subclass
```

Note that I've made the methods abstract by not providing any implementation. This means you'll need to create a concrete class that inherits from `DbgModuleMemory` and implements these methods according to your specific requirements.

Also, Python doesn't have built-in support for generics like Java does with its type system. The `List<String>` in the original code is equivalent to a list of strings (`[]`) in Python.