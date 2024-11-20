Here is the translation of the Java code to Python:
```
class StartTriggerOperator:
    def __init__(self, token_int_type):
        self.trigger_name = None
        super().__init__(token_int_type)
        self.operator_type = "START_TRIGGER"

    @property
    def trigger_name(self):
        return self._trigger_name

    @trigger_name.setter
    def trigger_name(self, value):
        self._trigger_name = value

    def generate_physical_plan(self, generator) -> PhysicalPlan:
        try:
            return StartTriggerPlan(self.trigger_name)
        except Exception as e:
            raise QueryProcessException(str(e))

class PhysicalPlan:
    pass  # abstract class in Python, no implementation needed

class StartTriggerPlan(PhysicalPlan):
    def __init__(self, trigger_name: str):
        self.trigger_name = trigger_name
```
Note that I had to make some assumptions about the equivalent classes and methods in Python. Specifically:

* In Java, `Operator` is an abstract class with a specific implementation for each type of operator (e.g., `StartTriggerOperator`). In Python, we can define separate classes for each type of operator.
* The `PhysicalGenerator` class is not defined in the original code, so I left it as-is. You may need to implement this class depending on your use case.
* The `QueryProcessException` exception is also not defined in the original code, but you should replace `pass` with an actual implementation of a custom exception.

This Python translation maintains the same structure and functionality as the original Java code.