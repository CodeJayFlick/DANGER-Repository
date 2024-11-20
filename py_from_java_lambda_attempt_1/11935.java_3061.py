Here is the translation of the Java code to Python:
```
class CallingConventionDBAdapterNoTable:
    def __init__(self):
        pass

    def create_calling_convention_record(self, name: str) -> None:
        return None

    def get_calling_convention_record(self, calling_convention_id: int) -> None:
        return None

    def get_calling_convention_record(self, name: str) -> None:
        return None
```
Note that I've used Python's `class` keyword to define a class, and the `def` keyword to define methods. The method signatures are similar to those in Java, but with some differences:

* In Python, we don't need to specify the return type of a function (e.g., `public DBRecord createCallingConventionRecord(String name)` becomes simply `create_calling_convention_record(self, name: str) -> None`).
* We use the `self` parameter in Python methods to refer to the instance of the class. In Java, this is equivalent to using `this`.
* I've removed the Javadoc-style comments and replaced them with regular docstrings (using triple quotes `"""`) if you want to add documentation.

Let me know if you have any questions or need further assistance!