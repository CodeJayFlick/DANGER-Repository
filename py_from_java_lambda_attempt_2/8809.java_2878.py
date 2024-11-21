Here is the translation of the Java interface `VTProgramCorrelatorInfo` to a Python class:
```
class VTProgramCorrelatorInfo:
    def get_name(self):
        pass  # implement me!

    def get_correlator_class_name(self):
        pass  # implement me!

    def get_options(self):
        pass  # implement me!

    def get_destination_address_set(self):
        pass  # implement me!

    def get_source_address_set(self):
        pass  # implement me!
```
Note that in Python, we don't have a direct equivalent to Java's `interface` keyword. Instead, we define a class with abstract methods (i.e., methods that are declared but not implemented). The `pass` statements indicate where the implementation should go.

Also note that Python does not require explicit getter and setter methods like Java does; you can simply access attributes directly using dot notation (e.g., `obj.name`).