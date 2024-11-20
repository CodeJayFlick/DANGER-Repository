Here is the translation of the Java code into Python:

```Python
class IpswFileSystem:
    def __init__(self, file_system_name: str, provider):
        pass  # equivalent to super(filesystemName, provider)

    @property
    def valid(self) -> bool:
        return False

    def open(self, monitor=None):
        pass  # does nothing yet

    def get_listing(self, directory) -> list:
        return []

    def get_byte_provider(self, file: str, monitor=None) -> bytes:
        return None


# Note that Python doesn't have direct equivalent of Java's annotations.
```

Here are some key differences between the two languages:

1.  **Class Definition**: In Java, classes are defined using `public class` syntax. In Python, you can define a class without any special keywords.

2.  **Method Overriding**: In Java, method overriding is done by providing an exact same signature as the parent class's method (including return type and parameter list). In Python, there isn't direct equivalent of method overriding like in Java. Instead, you would use inheritance to achieve similar functionality.

3.  **Property Decorators**: Python doesn't have property decorators like `@property` which is used in Java for getter/setter methods. You can define these as separate functions or properties with a setter and getter function.

4.  **Type Hints**: In Python, you can use type hints to specify the expected types of variables (like `str`, `int`, etc.). This doesn't affect runtime behavior but helps in code readability and static analysis tools like mypy.

5.  **Null/None Values**: Java has a null keyword for representing absence of any object value. Python uses None as its equivalent.

6.  **Exception Handling**: In Java, you can throw exceptions using `throws` clause at method level or catch them with try-catch blocks. In Python, you use the same try-except block to handle exceptions.