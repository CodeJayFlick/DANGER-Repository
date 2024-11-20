Here is the translation of the given Java interface into a Python class:

```Python
class TraceMemoryManager:
    def create_overlay_address_space(self, name: str, base: 'AddressSpace') -> 'AddressSpace':
        # Implement this method as per your requirements.
        pass  # This line should be replaced with actual implementation.

    def delete_overlay_address_space(self, name: str):
        # Implement this method as per your requirements.
        pass  # This line should be replaced with actual implementation.

    def get_memory_space(self, space: 'AddressSpace', create_if_absent: bool) -> 'TraceMemorySpace':
        if not create_if_absent:
            return None
        else:
            # Implement this method as per your requirements.
            pass  # This line should be replaced with actual implementation.

    def get_memory_register_space(self, thread: 'TraceThread', frame: int, create_if_absent: bool) -> 'TraceMemoryRegisterSpace':
        if not create_if_absent:
            return None
        else:
            # Implement this method as per your requirements.
            pass  # This line should be replaced with actual implementation.

    def get_memory_register_space(self, thread: 'TraceThread', create_if_absent: bool) -> 'TraceMemoryRegisterSpace':
        if not create_if_absent:
            return None
        else:
            # Implement this method as per your requirements.
            pass  # This line should be replaced with actual implementation.

    def get_memory_register_space(self, frame: 'TraceStackFrame', create_if_absent: bool) -> 'TraceMemoryRegisterSpace':
        if not create_if_absent:
            return None
        else:
            # Implement this method as per your requirements.
            pass  # This line should be replaced with actual implementation.

    def get_regions_added(self, from: int, to: int):
        # Implement this method as per your requirements.
        pass  # This line should be replaced with actual implementation.

    def get_regions_removed(self, from: int, to: int):
        # Implement this method as per your requirements.
        pass  # This line should be replaced with actual implementation.

    def get_state_changes(self, from: int, to: int) -> list:
        # Implement this method as per your requirements.
        return []  # This line should be replaced with actual implementation.
```

Please note that the Python code does not have direct equivalent of Java's `extends` keyword. The classes and interfaces are defined separately in Python.