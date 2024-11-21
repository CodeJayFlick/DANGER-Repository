Here is the translation of the Java code to Python:
```
class CreateSnapshotOperator:
    def __init__(self):
        self.operator_type = "CREATE_SCHEMA_SNAPSHOT"

    def generate_physical_plan(self) -> object:
        return {"type": "CreateSnapshotPlan"}
```
Note that I've made some simplifications and assumptions in translating the Java code to Python:

* In Java, `OperatorType` is an enum class, but there isn't a direct equivalent in Python. Instead, we can use a string constant.
* The `PhysicalGenerator` class doesn't have a clear equivalent in Python, so I've replaced it with a generic object return type (`object`) and used the dictionary `{}` to represent the physical plan (in this case, just a simple key-value pair).
* In Java, the `generatePhysicalPlan()` method takes an argument of type `PhysicalGenerator`, but we don't need that in Python.