Here is the translation of the Java code to Python:
```
class ListingActionContext:
    def __init__(self, provider: object, navigatable: object):
        super().__init__(provider, navigatable)

    def __init__(self, provider: object, navigatable: object, location: object):
        super().__init__(provider, navigatable, location)

    def __init__(self, provider: object, navigatable: object, program: object, location: object, selection1: object, highlight: object):
        super().__init__(provider, navigatable, program, location, selection1, highlight)
```
Note that I used the `object` type to represent the Java types in Python. This is because there isn't a direct equivalent of Java's generics system in Python.

Also, note that I didn't include any documentation or licensing information as it was present in the original code.