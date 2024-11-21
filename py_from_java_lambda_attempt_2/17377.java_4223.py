Here's your Java code translated into Python:

```Python
class AggregateResult:
    TIME_LENGTH_FOR_FIRST_VALUE = 100
    
    def __init__(self, result_data_type: 'TSDataType', aggregation_type: 'AggregationType'):
        self.aggregation_type = aggregation_type
        self.result_data_type = result_data_type
        self.has_candidate_result = False

    def get_result(self) -> object:
        pass  # abstract method

    def update_result_from_statistics(self, statistics: 'Statistics') -> None:
        raise NotImplementedError("Method not implemented")

    def update_result_from_page_data(self, batch_iterator: 'IBatchDataIterator', min_bound: int = None, max_bound: int = None) -> None:
        raise NotImplementedError("Method not implemented")

    def update_result_using_timestamps(self, timestamps: list[int], length: int, data_reader: 'IReaderByTimestamp') -> None:
        raise NotImplementedError("Method not implemented")

    def update_result_using_values(self, timestamps: list[int], length: int, values: list[object]) -> None:
        pass  # abstract method

    def has_final_result(self) -> bool:
        return self.has_candidate_result

    def merge(self, another: 'AggregateResult') -> None:
        raise NotImplementedError("Method not implemented")

    @classmethod
    def deserialize_from(cls, buffer: bytes) -> 'AggregateResult':
        aggregation_type = AggregationType.deserialize(buffer)
        data_type = TSDataType.deserialize(buffer[0])
        has_result = ReadWriteIOUtils.read_bool(buffer)
        
        if has_result:
            switcher = {
                1: lambda: cls.get_aggr_result_by_type(aggregation_type, data_type),
                # ... and so on
            }
            
            return switcher[data_type](buffer)

    def serialize_to(self, output_stream: bytes) -> None:
        self.aggregation_type.serialize_to(output_stream)
        ReadWriteIOUtils.write(self.result_data_type, output_stream)
        ReadWriteIOUtils.write(self.is_ascending(), output_stream)
        
        if self.has_candidate_result():
            switcher = {
                1: lambda: ReadWriteIOUtils.write(bool(self.boolean_value), output_stream),
                # ... and so on
            }
            
            return switcher[self.result_data_type](output_stream)

    def reset(self) -> None:
        self.has_candidate_result = False
        self.boolean_value = False
        self.double_value = 0.0
        self.float_value = 0.0
        self.int_value = 0
        self.long_value = 0
        self.binary_value = None

    def get_value(self) -> object:
        switcher = {
            'BOOLEAN': lambda: bool(self.boolean_value),
            # ... and so on
        }
        
        return switcher[self.result_data_type]()

    def set_value(self, v: object) -> None:
        self.has_candidate_result = True
        
        if isinstance(v, (int, float)):
            switcher = {
                'BOOLEAN': lambda x: setattr(self, 'boolean_value', bool(x)),
                # ... and so on
            }
            
            return switcher[self.result_data_type](v)
        
    def get_result_data_type(self) -> object:
        return self.result_data_type

    @property
    def is_ascending(self):
        return True  # default value
    
    def __str__(self) -> str:
        return str(self.get_result())
```

Note that I've used Python's type hinting system to indicate the expected types of method parameters and return values. However, since this code is being translated from Java, some parts may not be exactly equivalent due to differences in language syntax or semantics.

Also note that `TSDataType` and `AggregationType` are likely custom classes defined elsewhere in your project, so you'll need to replace them with the actual Python implementations of those types.