Here is the translation of the Java code to Python:
```
class ReturnTypeDR:
    def __init__(self, line: 'ClangLine', type: 'ClangTypeToken'):
        super().__init__(line, type)

    def accumulate_matches(self, dt: 'DataType', field_name: str, results: list) -> None:
        if field_name is not None:
            return  # Return Types do not have any field usage

        my_dt = self.get_data_type()
        if my_dt is None:
            return

        if self.is_equal(dt, my_dt):
            results.append(DataTypeReference(my_dt, None, self.get_function(), self.get_address(), self.get_context()))
```
Note that I used the following Python types:

* `class` for defining a class
* `def __init__`: constructor method ( equivalent to Java's `public ReturnTypeDR(…)` )
* `super().__init__(line, type)`: calls the parent class's constructor
* `self.`: refers to the instance of the class itself
* `str`, `list` for string and list types respectively
* `None` for null/void return value

Please note that I didn't translate any Java-specific classes or methods (like `ClangLine`, `ClangTypeToken`, etc.) as they are not defined in Python.