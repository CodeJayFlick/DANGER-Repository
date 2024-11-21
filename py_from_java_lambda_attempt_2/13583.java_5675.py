Here is the translation of the Java code to Python:
```
import ghidraprojectutils  # assuming this module exists in your project

class GhidraProjectPropertyTester:
    def test(self, receiver: object, property: str, args: list, expected_value: object) -> bool:
        return ghidraprojectutils.is_ghidra_project(ghidraprojectutils.get_enclosing_project(receiver))
```
Note that I've made the following assumptions:

* The `GhidraProjectUtils` class is defined in a separate module called `ghidraprojectutils`.
* The `is_Ghidra_Project` and `get_enclosing_project` methods are part of this `GhidraProjectUtils` class.
* Python's type hints (`: object`, etc.) are used to indicate the types of the method parameters.

Please adjust these assumptions according to your actual code structure.