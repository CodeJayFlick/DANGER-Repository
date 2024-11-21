Here is the translation of the Java code to Python:
```
class RegisterTypeInfo:
    def __init__(self, type: 'DataType', pointer_space: 'AddressSpace'):
        self.type = type
        self.settings = type.get_default_settings()
        self.pointer_space = pointer_space

    @property
    def value_class(self) -> type:
        return self.type.value_class(self.settings)
```
Note that I've used Python's type hinting system to indicate the types of the `type` and `pointer_space` parameters, as well as the return type of the `value_class` property. This is not strictly necessary for the code to work, but it can help with static analysis and documentation.

Also, in Python, we don't need a separate constructor method like Java does; instead, we define an `__init__` method that gets called when an instance of the class is created. The `@property` decorator allows us to define a read-only property (`value_class`) on the class.