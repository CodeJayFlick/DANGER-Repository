Here is the translation of the Java code to Python:
```
class SetStorageGroupOperator:
    def __init__(self, token_int_type):
        self.operator_type = "SET_STORAGE_GROUP"
        super().__init__(token_int_type)

    @property
    def path(self):
        return self._path

    @path.setter
    def set_path(self, value):
        self._path = value

    def generate_physical_plan(self, generator):
        from physical import SetStorageGroupPlan
        return SetStorageGroupPlan(self.path)
```
Note that I've used Python's built-in `property` decorator to create a getter and setter for the `path` attribute. This is equivalent to Java's private field with public getter and setter methods.

I've also removed the unnecessary imports, as they are not required in this translation. The `SetStorageGroupPlan` class is assumed to be defined elsewhere in your Python codebase.