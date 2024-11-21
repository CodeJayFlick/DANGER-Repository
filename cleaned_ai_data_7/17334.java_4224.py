class LoadDataPlan:
    def __init__(self, input_file_path: str, measure_type: str):
        super().__init__()
        self.input_file_path = input_file_path
        self.measure_type = measure_type

    @property
    def paths(self) -> list[PartialPath]:
        if self.measure_type is not None:
            return [PartialPath([self.measure_type])]
        else:
            return []

    @property
    def input_file_path(self):
        return self._input_file_path

    @input_file_path.setter
    def input_file_path(self, value: str):
        self._input_file_path = value

    @property
    def measure_type(self):
        return self._measure_type

    @measure_type.setter
    def measure_type(self, value: str):
        self._measure_type = value

    def __eq__(self, other) -> bool:
        if self is other:
            return True
        elif not isinstance(other, LoadDataPlan):
            return False
        else:
            return (self.input_file_path == other.input_file_path and
                    self.measure_type == other.measure_type)

    def __hash__(self) -> int:
        return hash((self.input_file_path, self.measure_type))
