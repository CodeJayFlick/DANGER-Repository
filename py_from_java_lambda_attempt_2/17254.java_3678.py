Here is the translation of the Java code to Python:
```
class DropTriggerOperator:
    def __init__(self):
        self.operator_type = "DROP_TRIGGER"

    def set_trigger_name(self, trigger_name: str) -> None:
        self.trigger_name = trigger_name

    def get_trigger_name(self) -> str:
        return self.trigger_name

    def generate_physical_plan(self, generator) -> object:
        try:
            return DropTriggerPlan(self.trigger_name)
        except Exception as e:
            raise QueryProcessException(str(e))
```
Note that I made the following changes:

* Renamed `Operator` to `DropTriggerOperator`, since it's a specific class.
* Removed the `tokenIntType` parameter, which doesn't seem to be used in the Java code either.
* Changed the type of `operator_type` from an enum (`OperatorType`) to a string constant.
* Replaced the `QueryProcessException` constructor with a simple `str(e)` conversion, since Python's exception handling is different from Java's.

Also note that I didn't include any imports or licenses in this code snippet, as they are not relevant to the translation itself.