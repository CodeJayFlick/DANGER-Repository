from abc import ABCMeta, abstractmethod
import io


class TSRecordConverter(metaclass=ABCMeta):
    @abstractmethod
    def open(self, schema: 'Schema') -> None:
        pass

    @abstractmethod
    def convert(self, input_data: object, collector) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        pass


class Schema:
    # This class is not fully implemented as it was in the Java code.
    pass


def open_converter(converter: TSRecordConverter, schema: 'Schema') -> None:
    converter.open(schema)


def convert_data(input_data: object, collector, converter: TSRecordConverter) -> None:
    try:
        converter.convert(input_data, collector)
    except io.IOException as e:
        print(f"Error converting data. {e}")


def close_converter(converter: TSRecordConverter) -> None:
    try:
        converter.close()
    except io.IOException as e:
        print(f"Error closing the converter. {e}")
