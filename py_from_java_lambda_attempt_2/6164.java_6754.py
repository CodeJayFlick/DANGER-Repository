Here is the translation of the Java code to Python:
```
class DirDataNameColumn:
    def __init__(self):
        pass

    def get_value(self, row_object: 'DirData', settings=None) -> str:
        return row_object.name

    def get_column_name(self) -> str:
        return "Name"
```
Note that I've used Python's type hints to indicate the types of the `row_object` and `settings` parameters. In Python, you don't need to explicitly declare classes or methods like you do in Java.

Also, since there is no equivalent concept to Java's `ServiceProvider` class in Python, I simply omitted it from the translation. If you need to access a service provider-like object in your Python code, you would typically use a separate variable or function parameter instead.