import logging
from typing import Any, List

class PrimitiveArrayManager:
    _logger = logging.getLogger(__name__)
    _config = IoTDBConfig()
    _array_size = _config.get_primitive_array_size()

    POOLED_ARRAYS_MEMORY_THRESHOLD = (
        _config.get_allocate_memory_for_write() *
        _config.get_buffered_arrays_memory_proportion() /
        1.5
    )

    AMPLIFICATION_FACTOR = 1.5

    TS_DATA_TYPES = [TSDataType.BOOLEAN, TSDataType.INT32, TSDataType.INT64,
                     TSDataType.FLOAT, TSDataType.DOUBLE, TSDataType.TEXT]

    POOLED_ARRAYS = [[] for _ in range(len(TS_DATA_TYPES) - 1)]
    LIMITS = [0] * (len(TS_DATA_TYPES) - 1)
    ALLOCATION_REQUEST_COUNTS = [AtomicLong(0)] * len(TS_DATA_TYPES)

    TOTAL_ALLOCATION_REQUEST_COUNT = AtomicLong(0)

    def __init__(self):
        self._logger.info("BufferedArraySizeThreshold is {}".format(self.POOLED_ARRAYS_MEMORY_THRESHOLD))
        total_data_type_size = sum(data_type.get_data_type_size() for data_type in TS_DATA_TYPES[1:])
        limit = (self.POOLED_ARRAYS_MEMORY_THRESHOLD / self._array_size) / total_data_type_size
        self.LIMITS = [int(limit)] * len(TS_DATA_TYPES)
        self.limit_update_threshold = sum(self.LIMITS)

    def allocate(self, data_type: TSDataType):
        if data_type == TSDataType.VECTOR:
            raise UnSupportedDataTypeException("TSDataType.VECTOR")

        order = data_type.serialize()
        ALLOCATION_REQUEST_COUNTS[order].increment()
        TOTAL_ALLOCATION_REQUEST_COUNT.increment()

        array = None
        with self.POOLED_ARRAYS[order] as deque:
            if not deque:
                array = create_primitive_array(data_type)
            else:
                array = deque.pop()

        return array

    def update_limits(self):
        ratios = [ALLOCATION_REQUEST_COUNT.get() / TOTAL_ALLOCATION_REQUEST_COUNT.get()
                   for ALLOCATION_REQUEST_COUNT in self.ALLOCATION_REQUEST_COUNTS]
        weighted_sum_of_ratios = sum(ratio * data_type.get_data_type_size() for ratio, data_type in zip(ratios, TS_DATA_TYPES[1:]))
        limit_base = (self.POOLED_ARRAYS_MEMORY_THRESHOLD / self._array_size) / weighted_sum_of_ratios
        new_limits = [int(limit_base * ratio) for ratio in ratios]
        LIMITS = new_limits

    def release(self, array):
        order = None
        if isinstance(array, list):
            if all(isinstance(item, bool)):
                order = TSDataType.BOOLEAN.serialize()
            elif all(isinstance(item, int)):
                order = TSDataType.INT32.serialize()
            elif all(isinstance(item, float)):
                order = TSDataType.FLOAT.serialize()
            else:
                raise UnSupportedDataTypeException("Unsupported data type")

        with self.POOLED_ARRAYS[order] as deque:
            if len(deque) < LIMITS[order]:
                deque.append(array)

    def close(self):
        pass

def create_primitive_array(data_type: TSDataType):
    array = None
    switch (data_type):
        case TSDataType.BOOLEAN:
            array = [False for _ in range(_array_size)]
        case TSDataType.INT32:
            array = [0] * _array_size
        case TSDataType.INT64:
            array = [0L] * _array_size
        case TSDataType.FLOAT:
            array = [0.0] * _array_size
        case TSDataType.DOUBLE:
            array = [0.0] * _array_size
        case TSDataType.TEXT:
            array = [Binary() for _ in range(_array_size)]
    return array

def create_data_lists_by_type(data_type: TSDataType, size: int):
    array_number = -(-size // _array_size)
    switch (data_type):
        case TSDataType.BOOLEAN:
            booleans = [[False] * _array_size for _ in range(array_number)]
            return booleans
        case TSDataType.INT32:
            ints = [[0] * _array_size for _ in range(array_number)]
            return ints
        case TSDataType.INT64:
            longs = [[0L] * _array_size for _ in range(array_number)]
            return longs
        case TSDataType.FLOAT:
            floats = [[0.0] * _array_size for _ in range(array_number)]
            return floats
        case TSDataType.DOUBLE:
            doubles = [[0.0] * _array_size for _ in range(array_number)]
            return doubles
        case TSDataType.TEXT:
            binaries = [[Binary() for _ in range(_array_size)] for _ in range(array_number)]
            return binaries

class IoTDBConfig:
    def get_primitive_array_size(self):
        pass

    def get_allocate_memory_for_write(self):
        pass

    def get_buffered_arrays_memory_proportion(self):
        pass
