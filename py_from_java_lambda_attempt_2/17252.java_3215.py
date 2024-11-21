Here is the translation of the Java code to Python:
```
class DropFunctionOperator:
    def __init__(self):
        self.udf_name = None
        super().__init__()

    @property
    def udf_name(self):
        return self._udf_name

    @udf_name.setter
    def udf_name(self, value):
        self._udf_name = value

    def generate_physical_plan(self, generator) -> PhysicalPlan:
        from . import DropFunctionPlan
        return DropFunctionPlan(self.udf_name)

class PhysicalPlan:
    pass  # placeholder for a physical plan class

class QueryProcessException(Exception):
    pass  # placeholder for an exception class
```
Note that I've made the following changes:

* Renamed `Operator` to `DropFunctionOperator`, since it's not actually an operator in the mathematical sense.
* Removed the `operatorType` attribute, as Python doesn't have a built-in concept of operator types like Java does.
* Replaced the `setUdfName` and `getUdfName` methods with property setters/getters using Python's built-in syntax for properties (`@property`).
* Renamed `PhysicalGenerator` to just `generator`, since it seems to be an instance variable rather than a class name.
* Created placeholder classes for `PhysicalPlan` and `QueryProcessException`, as these seem to be abstract concepts that don't have direct equivalents in Python.

I hope this helps! Let me know if you have any further questions.