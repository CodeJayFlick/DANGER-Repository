Here is the translation of the given Java code into equivalent Python:

```Python
class ElasticSerializableTVList:
    def __init__(self, data_type: TSDataType, query_id: int, memory_limit_in_mb: float, cache_size: int):
        self.data_type = data_type
        self.query_id = query_id
        self.memory_limit_in_mb = memory_limit_in_mb
        self.cache_size = cache_size

    def get_data_type(self) -> TSDataType:
        return self.data_type

    def size(self) -> int:
        return self.size_

    def time(self, index: int) -> int:
        if 0 <= index < self.size_ / self.internal_tv_list_capacity:
            return self.cache_[index // self.internal_tv_list_capacity].time_by_index(index % self.internal_tv_list_capacity)
        else:
            raise IndexError("Index out of range")

    def get_int(self, index: int) -> int:
        if 0 <= index < self.size_ / self.internal_tv_list_capacity:
            return self.cache_[index // self.internal_tv_list_capacity].get_int_by_index(index % self.internal_tv_list_capacity)
        else:
            raise IndexError("Index out of range")

    def get_long(self, index: int) -> int:
        if 0 <= index < self.size_ / self.internal_tv_list_capacity:
            return self.cache_[index // self.internal_tv_list_capacity].get_long_by_index(index % self.internal_tv_list_capacity)
        else:
            raise IndexError("Index out of range")

    def get_float(self, index: int) -> float:
        if 0 <= index < self.size_ / self.internal_tv_list_capacity:
            return self.cache_[index // self.internal_tv_list_capacity].get_float_by_index(index % self.internal_tv_list_capacity)
        else:
            raise IndexError("Index out of range")

    def get_double(self, index: int) -> float:
        if 0 <= index < self.size_ / self.internal_tv_list_capacity:
            return self.cache_[index // self.internal_tv_list_capacity].get_double_by_index(index % self.internal_tv_list_capacity)
        else:
            raise IndexError("Index out of range")

    def get_boolean(self, index: int) -> bool:
        if 0 <= index < self.size_ / self.internal_tv_list_capacity:
            return self.cache_[index // self.internal_tv_list_capacity].get_boolean_by_index(index % self.internal_tv_list_capacity)
        else:
            raise IndexError("Index out of range")

    def get_binary(self, index: int) -> Binary:
        if 0 <= index < self.size_ / self.internal_tv_list_capacity:
            return self.cache_[index // self.internal_tv_list_capacity].get_binary_by_index(index % self.internal_tv_list_capacity)
        else:
            raise IndexError("Index out of range")

    def put(self, timestamp: int, value):
        if isinstance(value, int):
            self.put_int(timestamp, value)
        elif isinstance(value, float):
            self.put_float(timestamp, value)
        elif isinstance(value, bool):
            self.put_boolean(timestamp, value)
        else:
            raise ValueError("Unsupported data type")

    def put_int(self, timestamp: int, value: int) -> None:
        if self.size_ % self.internal_tv_list_capacity == 0:
            self.tv_lists.append(SerializableTVList.new_serializable_tv_list(self.data_type, self.query_id))
        self.cache_[self.size_ // self.internal_tv_list_capacity].put_int(timestamp, value)
        self.size_ += 1

    def put_float(self, timestamp: int, value: float) -> None:
        if self.size_ % self.internal_tv_list_capacity == 0:
            self.tv_lists.append(SerializableTVList.new_serializable_tv_list(self.data_type, self.query_id))
        self.cache_[self.size_ // self.internal_tv_list_capacity].put_float(timestamp, value)
        self.size_ += 1

    def put_boolean(self, timestamp: int, value: bool) -> None:
        if self.size_ % self.internal_tv_list_capacity == 0:
            self.tv_lists.append(SerializableTVList.new_serializable_tv_list(self.data_type, self.query_id))
        self.cache_[self.size_ // self.internal_tv_list_capacity].put_boolean(timestamp, value)
        self.size_ += 1

    def put_binary(self, timestamp: int, binary_value):
        if self.size_ % self.internal_tv_list_capacity == 0:
            self.tv_lists.append(SerializableTVList.new_serializable_tv_list(self.data_type, self.query_id))
        self.cache_[self.size_ // self.internal_tv_list_capacity].put_binary(timestamp, binary_value)
        self.size_ += 1

    def construct_point_reader_using_trivial_eviction_strategy(self) -> LayerPointReader:
        return LayerPointReader(
            current_point_index=-1,
            eviction_upper_bound=self.eviction_upper_bound
        )

    def set_eviction_upper_bound(self, index: int):
        self.eviction_upper_bound = index

class LRUCache:
    def __init__(self, capacity: int):
        super().__init__(capacity)

    def get(self, target_index) -> BatchData:
        if not remove_first_occurrence(target_index):
            if cache_capacity <= cache_size:
                last_index = remove_last()
                if last_index < eviction_upper_bound // internal_tv_list_capacity:
                    tv_lists.set(last_index, None)
                else:
                    tv_lists.get(last_index).serialize()
            tv_lists.get(target_index).deserialize()
        add_first(target_index)
        return tv_lists.get(target_index)

class SerializableTVList:
    @staticmethod
    def new_serializable_tv_list(data_type: TSDataType, query_id: int) -> 'SerializableTVList':
        # implementation

class LayerPointReader:
    def __init__(self):
        self.current_point_index = -1
        self.eviction_upper_bound = 0

    def next(self) -> bool:
        if size_ - 1 <= current_point_index:
            return False
        else:
            current_point_index += 1
            return True

    def ready_for_next(self):
        set_eviction_upper_bound(current_point_index + 1)

    def get_data_type(self) -> TSDataType:
        # implementation

    def current_time(self) -> int:
        if 0 <= self.current_point_index < size_ / internal_tv_list_capacity:
            return time_(self.current_point_index)
        else:
            raise IndexError("Index out of range")

    def current_int(self) -> int:
        if 0 <= self.current_point_index < size_ / internal_tv_list_capacity:
            return get_int_(self.current_point_index)
        else:
            raise IndexError("Index out of range")
```

Please note that the `TSDataType`, `SerializableTVList`, and other classes are not implemented in this translation. You would need to implement these yourself based on your specific requirements.

Also, please be aware that Python does not have a direct equivalent to Java's checked exceptions.