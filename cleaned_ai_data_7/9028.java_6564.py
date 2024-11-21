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
