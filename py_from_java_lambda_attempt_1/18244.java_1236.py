Here is the translation of the Java interface `Filter` into a Python class:

```Python
class Filter:
    def __init__(self):
        pass

    def satisfy(self, statistics: 'Statistics') -> bool:
        """To examine whether the statistics is satisfied with the filter."""
        raise NotImplementedError("Method not implemented")

    def satisfy(self, time: int, value) -> bool:
        """To examine whether the single point(with time and value) is satisfied with the filter."""
        raise NotImplementedError("Method not implemented")

    def satisfy_start_end_time(self, start_time: int, end_time: int) -> bool:
        """To examine whether the min time and max time are satisfied with the filter."""
        raise NotImplementedError("Method not implemented")

    def contain_start_end_time(self, start_time: int, end_time: int) -> bool:
        """To examine whether the partition [startTime, endTime] is subsets of filter."""
        raise NotImplementedError("Method not implemented")

    def copy(self):
        return self.__class__()

    def serialize(self, output_stream):
        pass

    def deserialize(self, buffer):
        pass

    def get_serialize_id(self) -> 'FilterSerializeId':
        """To examine whether the partition [startTime, endTime] is subsets of filter."""
        raise NotImplementedError("Method not implemented")
```

Note that I've used Python's type hinting to indicate what types each method should accept and return.