import io


class FixLengthTimeValuePairSerializer:
    def __init__(self, tmp_file_path):
        self.check_path(tmp_file_path)
        self.output_stream = open(tmp_file_path, 'wb')

    def write(self, time_value_pair: tuple) -> None:
        if not hasattr(self, 'data_type_defined'):
            self.set_writer(time_value_pair[1])
            self.write_header(time_value_pair[1])
            setattr(self, 'data_type_defined', True)

        writer = getattr(self, f'writer_{time_value_pair[1].__class__.__name__.lower()}')
        writer.write(time_value_pair, self.output_stream)

    def close(self) -> None:
        self.output_stream.close()

    def write_header(self, data_type: int) -> None:
        self.output_stream.write(data_type.to_bytes(4, 'big'))

    def check_path(self, tmp_file_path: str) -> None:
        file = open(tmp_file_path, 'wb')
        if os.path.exists(file.name):
            os.remove(file.name)
        parent_dir = os.path.dirname(file.name)
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir)
        file.close()
        file = open(tmp_file_path, 'ab')

    def set_writer(self, data_type: int) -> None:
        self.writer = {
            0x01: lambda tv_pair: BinaryWriter(tv_pair),
            0x02: lambda tv_pair: IntWriter(tv_pair),
            0x03: lambda tv_pair: LongWriter(tv_pair),
            0x04: lambda tv_pair: FloatWriter(tv_pair),
            0x05: lambda tv_pair: DoubleWriter(tv_pair)
        }[data_type]

    def __del__(self):
        self.close()


class TimeValuePairWriter:
    @abstractmethod
    def write(self, time_value_pair: tuple, output_stream: io.IOBase) -> None:


class BinaryWriter(TimeValuePairWriter):
    def write(self, time_value_pair: tuple, output_stream: io.IOBase) -> None:
        output_stream.write(time_value_pair[0].to_bytes(8, 'big'))
        output_stream.write(len(time_value_pair[1]).to_bytes(4, 'big'))
        output_stream.write(time_value_pair[1].encode('utf-8'))


class IntWriter(TimeValuePairWriter):
    def write(self, time_value_pair: tuple, output_stream: io.IOBase) -> None:
        output_stream.write(time_value_pair[0].to_bytes(8, 'big'))
        output_stream.write(int(time_value_pair[1]).to_bytes(4, 'big'))


class LongWriter(TimeValuePairWriter):
    def write(self, time_value_pair: tuple, output_stream: io.IOBase) -> None:
        output_stream.write(time_value_pair[0].to_bytes(8, 'big'))
        output_stream.write(long(time_value_pair[1]).to_bytes(8, 'big'))


class FloatWriter(TimeValuePairWriter):
    def write(self, time_value_pair: tuple, output_stream: io.IOBase) -> None:
        output_stream.write(time_value_pair[0].to_bytes(8, 'big'))
        output_stream.write(float(time_value_pair[1]).to_bytes(4, 'big'))


class DoubleWriter(TimeValuePairWriter):
    def write(self, time_value_pair: tuple, output_stream: io.IOBase) -> None:
        output_stream.write(time_value_pair[0].to_bytes(8, 'big'))
        output_stream.write(double(time_value_pair[1]).to_bytes(8, 'big'))

