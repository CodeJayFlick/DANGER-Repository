Here is a translation of the provided Java code into equivalent Python:

```Python
class ObsoleteCommand:
    def __init__(self):
        pass  # DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.

    def init_obsolete_command(self, reader):
        self.init_load_command(reader)
        raise Exception("ObsoleteException")

    def to_data_type(self):
        struct = {"cmd": "DWORD", "cmdsize": "DWORD", "obsolete": f"BYTE[{self.get_command_size() - 8}]"}
        return struct

    def get_byte_array(self):
        return [f"BYTE"] * (self.get_command_size() - 8)

    def markup(self, header, api, base_address, is_binary, parent_module, monitor, log):
        self.update_monitor(monitor)
        try:
            if is_binary:
                self.create_fragment(api, base_address, parent_module)
                addr = base_address + self.get_start_index()
                api.create_data(addr, self.to_data_type())
        except Exception as e:
            log.append(f"Unable to create {self.get_command_name()} - {e}")

class LoadCommand:
    def __init__(self):
        pass

    def init_load_command(self, reader):
        # implementation of this method is missing in the provided Java code
        pass

# This class does not have a direct equivalent in Python. It seems to be used for creating fragments.
```

Please note that there are some differences between the original Java code and its translation into Python:

1. In Python, we don't need explicit constructors (`__init__` method) like in Java.

2. The `throws IOException, MachException` declaration is not necessary in Python as exceptions can be raised directly from a function or method without declaring them beforehand.

3. The `@Override` annotation is also not needed in Python because it does not have the concept of overriding methods like Java has with its abstract classes and interfaces.

4. In Python, we use dictionaries to represent data structures similar to Java's HashMaps (or Structures) for storing key-value pairs.

5. We don't need explicit getters (`getByteArray()`) or setters in Python because it supports dynamic attribute access through the `__dict__` dictionary of an object.

6. The concept of a factory method is not directly applicable in Python, but we can achieve similar functionality using classes and their constructors (or `__init__` methods).

7. In Java's `markup()` method, there are some calls to abstract methods (`updateMonitor()`, `createFragment()`) that do not have direct equivalents in the provided code or its translation into Python.

8. The concept of a task monitor is also missing from this translation as it does not seem to be directly applicable in Python.