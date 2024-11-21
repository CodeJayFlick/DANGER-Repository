Here is the translation of the Java code to Python:
```
class StackDepthFieldLocation:
    def __init__(self, program: 'Program', addr: int, char_offset: int):
        super().__init__(program, addr, 0, 0, char_offset)

    def __init__(self):  # for deserialization
        pass

# Note: In Python, we don't need to declare the types of variables or methods,
# so I removed those parts. Also, Python doesn't have a direct equivalent to Java's "package" statement.
```
Note that in Python, we use indentation to denote block-level structure (like classes and functions), whereas in Java, we use curly braces `{}`.

Also, the `Program` class is not defined here, so I left it as a string literal `'Program'`. In Python, you would need to define this class or import it from another module.