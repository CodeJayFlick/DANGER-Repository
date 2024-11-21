Here is the translation of the Java code to Python:
```
class UserException(Exception):
    def __init__(self):
        super().__init__()

    def __init__(self, msg):
        super().__init__(msg)

    def __init__(self, msg, cause):
        super().__init__(msg, cause)
```
Note that in Python, we don't need to specify the `public` access modifier as it is not applicable. Also, the constructor (`__init__`) method is used instead of a separate constructor like in Java.

Also, note that Python's exception handling mechanism is different from Java's. In Python, you can raise an exception using the `raise` statement and catch exceptions using try-except blocks.