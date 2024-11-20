import io

class SingleSourceExternalSortJobPart:
    def __init__(self, chunk_reader_wrap):
        self.chunk_reader_wrap = chunk_reader_wrap
        super().__init__(type="SINGLE_SOURCE")

    def execute_for_i_point_reader(self) -> "IPointReader":
        return self.chunk_reader_wrap.get_i_point_reader()
