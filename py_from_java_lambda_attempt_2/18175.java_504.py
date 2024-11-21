Here is the translation of the Java code to Python:
```
class UnknownColumnTypeException(Exception):
    def __init__(self, column_type):
        super().__init__(f"Column type not found: {column_type}")

serialVersionUID = -4003170165687174659
```
Note that in Python:

* We don't need a `package` statement or an `import` statement for the exception class.
* The `class` keyword is used to define a new class, instead of `public`.
* The `extends` clause is not needed; we simply inherit from the built-in `Exception` class using parentheses in the class definition.
* We don't need a separate `serialVersionUID` variable declaration; it's implied by the use of the `super()` method.
* The constructor (`__init__`) takes only one argument, `column_type`, which is used to initialize the exception message.