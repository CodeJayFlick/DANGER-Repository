import io

class SymbolServerInputStream:
    def __init__(self, input_stream: 'io.IOBase', expected_length: int):
        self.input_stream = input_stream
        self.expected_length = expected_length

    @property
    def input_stream(self) -> 'io.IOBase':
        return self._input_stream

    @input_stream.setter
    def input_stream(self, value: 'io.IOBase'):
        self._input_stream = value

    @property
    def expected_length(self) -> int:
        return self._expected_length

    @expected_length.setter
    def expected_length(self, value: int):
        self._expected_length = value

    def close(self) -> None:
        try:
            self.input_stream.close()
        except Exception as e:
            raise IOError(str(e))
