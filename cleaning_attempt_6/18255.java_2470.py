class In:
    def __init__(self):
        pass

    def __init__(self, values: set, filter_type: str, not_: bool) -> None:
        self.values = values
        self.filter_type = filter_type
        self.not_ = not_

    def satisfy(self, statistics: dict) -> bool:
        return True

    def satisfy(self, time: int, value: object) -> bool:
        v = value if self.filter_type == 'TIME_FILTER' else time
        return (v in self.values) != self.not_

    def satisfy_start_end_time(self, start_time: int, end_time: int) -> bool:
        return True

    def contain_start_end_time(self, start_time: int, end_time: int) -> bool:
        return True

    def copy(self) -> 'In':
        return In(set(self.values), self.filter_type, self.not_)

    def serialize(self, output_stream):
        try:
            output_stream.write(ord(self.get_serialize_id()))
            output_stream.write(ord(self.filter_type))
            ReadWriteIOUtils.write(output_stream, self.not_)
            output_stream.write(len(self.values))
            for value in self.values:
                ReadWriteIOUtils.write_object(value, output_stream)
        except Exception as e:
            print(f"Error: {e}")

    def deserialize(self, buffer):
        self.filter_type = chr(buffer.get())
        self.not_ = ReadWriteIOUtils.read_bool(buffer)
        self.values = set()
        for _ in range(buffer.get()):
            self.values.add(ReadWriteIOUtils.read_object(buffer))

    def __str__(self) -> str:
        value_list = list(self.values)
        value_list.sort()
        return f"{self.filter_type} < {f'reverse: {self.not_}, ' if not_ else ''}{value_list}"

    def get_serialize_id(self):
        return "IN"
