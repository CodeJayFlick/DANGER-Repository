Here is the translation of the Java code to Python:
```
import abc

class IFill(metaclass=abc.ABCMeta):
    def __init__(self, data_type: 'TSDataType', query_time: int) -> None:
        self._data_type = data_type
        self._query_time = query_time

    def __init__(self) -> None:
        pass  # default constructor

    @abc.abstractmethod
    def copy(self) -> 'IFill':
        raise NotImplementedError

    @abc.abstractmethod
    def configure_fill(
            self,
            path: str,
            data_type: 'TSDataType',
            query_time: int,
            device_measurements: set[str],
            context: dict  # assume QueryContext is a dictionary-like object
    ) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def get_fill_result(self) -> tuple[int, str]:
        raise NotImplementedError

    @property
    def data_type(self) -> 'TSDataType':
        return self._data_type

    @data_type.setter
    def data_type(self, value: 'TSDataType') -> None:
        self._data_type = value

    @property
    def query_time(self) -> int:
        return self._query_time

    @query_time.setter
    def query_time(self, value: int) -> None:
        self._query_time = value

    @abc.abstractmethod
    def construct_filter(self) -> None:
        raise NotImplementedError


class TSDataType:
    pass  # assume this is a Python enum or equivalent


def main() -> None:
    fill = IFill(TSDataType(), 123)
    print(fill.data_type, fill.query_time)

if __name__ == '__main__':
    main()
```
Note that I've used the `abc` module to define an abstract base class (ABC) in Python. This allows us to use the same syntax as Java for defining abstract methods and properties.

I've also assumed that `QueryContext` is a dictionary-like object, since there's no equivalent concept in Python like Java's `Map`. If you need more specific behavior from `QueryContext`, please let me know!