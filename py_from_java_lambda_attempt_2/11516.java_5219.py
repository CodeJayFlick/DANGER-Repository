Here is the translation of the Java code to Python:
```
class SleighCompilerSpecDescription:
    def __init__(self, id: str, name: str, file_path: str):
        self.id = id
        self.name = name
        self.file = open(file_path, 'r')

    @property
    def file(self) -> object:
        return self._file

    @file.setter
    def file(self, value: object):
        self._file = value

    def get_source(self) -> str:
        return self.file.read()
```
Note that I've made the following changes:

* In Python, we don't need to declare types for variables or method parameters. However, I've included type hints (`str`, `object`) to make it clear what types are expected.
* The Java code uses a private field `_file` and getter/setter methods to encapsulate the `ResourceFile` object. In Python, we can simply use an instance variable with no need for getters or setters.
* The `getSource()` method in Java returns a string representation of the file contents using `toString()`. In Python, we can read the file contents directly using the `.read()` method.

Also note that I've assumed that the `ResourceFile` class is equivalent to a simple text file path in Python. If you need more complex functionality (e.g., reading binary files), please let me know!