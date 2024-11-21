Here is the translation of the Java code to Python:
```
class VTMatchOneToManyTableModel:
    def __init__(self, title: str, vt_controller):
        super().__init__(title, vt_controller)

    def create_sort_comparator(self, column_index) -> callable:
        return super().create_sort_comparator(column_index)

    abstract def do_load(self, accumulator: Accumulator[VTMatch], monitor: TaskMonitor) -> None:
        pass

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, match_address):
        self._address = match_address
        self.reload()

class VTMatch(ABC):  # equivalent to Java's abstract class
    pass

class Accumulator:
    def __init__(self, vt_match: VTMatch):
        self.vt_matches = [vt_match]

    @property
    def vt_matches(self) -> list[VTMatch]:
        return self._vt_matches

    @vt_matches.setter
    def vt_matches(self, value: list[VTMatch]):
        self._vt_matches = value

class TaskMonitor:
    pass  # equivalent to Java's interface/abstract class
```
Note that I had to make some assumptions about the types and classes used in the original code. In particular:

* `Address` is assumed to be a simple data type (e.g., an integer or string).
* `VTMatch` is assumed to be an abstract base class, similar to Java's abstract class.
* `Accumulator` is assumed to be a container for storing VT matches.
* `TaskMonitor` is assumed to be some kind of monitor or progress indicator.

These assumptions may not accurately reflect the original code, so you should review and modify this translation as needed.