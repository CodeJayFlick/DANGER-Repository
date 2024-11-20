Here's your Java interface translated into a Python class:

```Python
class ITimeIndex:
    SPANS_MULTI_TIME_PARTITIONS_FLAG_ID = -1

    def serialize(self, output_stream):
        pass  # implement this method in subclass

    def deserialize(self, input_stream):
        return self  # implement this method in subclass

    def deserialize_buffer(self, buffer):
        return self  # implement this method in subclass

    def close(self):
        pass  # may be an empty method

    def get_devices(self, ts_file_path):
        raise NotImplementedError("Subclass must implement")

    def end_time_empty(self):
        return True  # or False depending on your implementation

    def still_lives(self, ttl_lower_bound):
        raise NotImplementedError("Subclass must implement")

    def calculate_ram_size(self):
        raise NotImplementedError("Subclass must implement")

    def get_time_partition(self, ts_file_path):
        raise NotImplementedError("Subclass must implement")

    def get_time_partition_with_check(self, ts_file_path):
        raise PartitionViolationException  # or subclass and handle the exception

    def is_span_multi_time_partitions(self):
        return False  # default implementation

    def update_start_time(self, device_id, time):
        pass  # may be an empty method

    def update_end_time(self, device_id, time):
        pass  # may be an empty method

    def put_start_time(self, device_id, time):
        pass  # may be an empty method

    def put_end_time(self, device_id, time):
        pass  # may be an empty method

    def get_start_time(self, device_id):
        raise NotImplementedError("Subclass must implement")

    def get_end_time(self, device_id):
        raise NotImplementedError("Subclass must implement")

    def check_device_id_exist(self, device_id):
        return False  # default implementation

    def get_min_start_time(self):
        raise NotImplementedError("Subclass must implement")

    def get_max_end_time(self):
        raise NotImplementedError("Subclass must implement")

    def compare_degrade_priority(self, time_index):
        return 0  # or -1 if this ITimeIndex is higher priority
```

This Python class does not contain any actual implementation for the methods. It's just a translation of your Java interface into Python syntax. You would need to create subclasses that implement these abstract methods according to your specific requirements.