Here is the translation of the Java code to Python:
```
class StopTriggerOperator:
    def __init__(self, token_int_type):
        self.trigger_name = None
        super().__init__(token_int_type)
        self.operator_type = "STOP_TRIGGER"

    @property
    def trigger_name(self):
        return self._trigger_name

    @trigger_name.setter
    def trigger_name(self, value):
        self._trigger_name = value

    def generate_physical_plan(self, generator) -> PhysicalPlan:
        from . import StopTriggerPlan  # assuming this is in a separate file
        try:
            return StopTriggerPlan(self.trigger_name)
        except Exception as e:
            raise QueryProcessException(str(e))

class PhysicalGenerator:
    pass

class PhysicalPlan:
    pass

class QueryProcessException(Exception):
    pass
```
Note that I've made the following changes:

* In Python, we don't need to specify types for variables or method parameters.
* The `private` keyword is not used in Python; instead, we use a convention of prefixing variable names with an underscore (`_`) to indicate they are private.
* The `@Override` annotation is not needed in Python, as it's implicit that the method is overriding a parent class method if its name matches exactly.
* I've assumed that the `StopTriggerPlan`, `PhysicalGenerator`, and `QueryProcessException` classes will be defined elsewhere in your codebase. If they are not, you'll need to define them or import them from another module.

Also note that this is just one possible translation of the Java code to Python; there may be other ways to achieve the same result using different syntax and conventions.