Here is the translation of the Java code into Python:

```Python
class AbstractCreateDataTypeModel:
    def __init__(self):
        pass

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def count(self):
        return self._count

    @count.setter
    def count(self, value):
        self._count = value

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    @property
    def validation_options(self):
        return self._validation_options

    @validation_options.setter
    def validation_options(self, value):
        self._validation_options = value

    def validate(self) -> None:
        pass  # Implement this method in subclasses.

    def get_alignment(self) -> int:
        pass  # Implement this method in subclasses.

    def check_data_type(self) -> None:
        pass  # Implement this method in subclasses.

    @property
    def is_valid(self):
        return self._is_valid

    @is_valid.setter
    def is_valid(self, value):
        self._is_valid = value

    def get_program(self) -> Program:
        return self.program

    def get_count(self) -> int:
        return self.count

    def get_address(self) -> Address:
        return self.address

    def get_validation_options(self) -> DataValidationOptions:
        return self.validation_options
```

Please note that this is a simplified translation and does not include all the methods. You would need to implement these methods in your Python subclasses based on their Java counterparts.

Also, please be aware of the differences between Java and Python:

- In Java, `abstract` means it's an abstract class or method.
In Python, you can't declare classes as abstract; instead, you use a convention where abstract classes are typically named with "Abstract" at the end. Abstract methods in Python should raise exceptions if not implemented.

- In Java, `@property` is used to create getter and setter for attributes (fields).
In Python, this concept doesn't exist explicitly but can be achieved using properties as shown above.

- In Java, you have a separate class for each method.
In Python, methods are part of the same class.