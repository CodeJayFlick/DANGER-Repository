Here is the translation of the Java code to Python:
```
class ShowStorageGroupPlan:
    def __init__(self, show_content_type: str, path: 'org.apache.iotdb.db.metadata.PartialPath'):
        self.path = path
        super().__init__(show_content_type)

    @property
    def path(self) -> 'org.apache.iotdb.db.metadata.PartialPath':
        return self._path

# Note: The `PartialPath` class is not a built-in Python type, so you would need to define it separately or use an existing equivalent.
```
Note that I used the following conventions:

* In Python, we don't have explicit getters and setters like in Java. Instead, we can use properties (e.g., `@property`) to provide read-only access to attributes.
* The `__init__` method is similar to the constructor in Java, but it's not called explicitly when creating an instance of the class.
* I used type hints for the `show_content_type` and `path` parameters, as well as for the return types of methods. This is optional, but can be helpful for code readability and static analysis tools.

Also note that you would need to define the `PartialPath` class separately or use an existing equivalent in Python.