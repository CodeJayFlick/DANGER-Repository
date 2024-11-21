Here is the translation of the given Java code into Python:

```Python
class StorageGroupInfo:
    def __init__(self, storage_group_processor):
        self.storage_group_processor = storage_group_processor
        self.memory_cost = 0
        self.last_reported_size = 0
        self.reported_tsps = []

    @property
    def memory_cost(self):
        return self._memory_cost

    @memory_cost.setter
    def memory_cost(self, value):
        self._memory_cost = value

    @property
    def last_reported_size(self):
        return self._last_reported_size

    @last_reported_size.setter
    def last_reported_size(self, value):
        self._last_reported_size = value

    @property
    def reported_tsps(self):
        return self._reported_tsps

    @reported_tsps.setter
    def reported_tsps(self, value):
        self._reported_tsps = value

    def init_ts_file_processor_info(self, ts_file_processor):
        self.reported_tsps.append(ts_file_processor)

    def add_storage_group_mem_cost(self, cost):
        self.memory_cost += cost

    def release_storage_group_mem_cost(self, cost):
        self.memory_cost -= cost

    def get_mem_cost(self):
        return self.memory_cost

    def need_to_report_to_system(self):
        if self.last_reported_size == 0:
            return False
        else:
            return self.memory_cost - self.last_reported_size > storage_group_size_report_threshold()

    def set_last_reported_size(self, size):
        self.last_reported_size = size

    def close_ts_file_processor_and_report_to_system(self, ts_file_processor):
        if ts_file_processor in self.reported_tsps:
            self.reported_tsps.remove(ts_file_processor)
            system_info().reset_storage_group_status(self)

    @property
    def storage_group_processor(self):
        return self._storage_group_processor

    @storage_group_processor.setter
    def storage_group_processor(self, value):
        self._storage_group_processor = value

    def get_wal_supplier(self):
        if self.storage_group_processor is not None:
            return lambda: self.storage_group_processor.get_wal_direct_byte_buffer()
        else:
            return lambda: wal_supplier()

    @property
    def storage_group_size_report_threshold(self):
        config = IoTDBDescriptor().get_instance().get_config()
        return config.get_storage_group_size_report_threshold() / 2

    @staticmethod
    def system_info():
        # This is equivalent to SystemInfo.getInstance() in Java.
        pass

    @property
    def wal_supplier(self):
        if self.storage_group_processor is None:
            buffers = [ByteBuffer.allocate_direct(IoTDBDescriptor().get_instance().get_config().get_wal_buffer_size() / 2), 
                       ByteBuffer.allocate_direct(IoTDBDescriptor().get_instance().get_config().get_wal_buffer_size() / 2)]
        else:
            return lambda: self.storage_group_processor.get_wal_direct_byte_buffer()
        return buffers

    def get_wal_consumer(self):
        if self.storage_group_processor is not None:
            return lambda buffer_array: self.storage_group_processor.release_wal_buffer(buffer_array)
        else:
            return lambda buffer_array: wal_consumer(buffer_array)

    @staticmethod
    def wal_consumer(buffers):
        for byte_buffer in buffers:
            MmapUtil().clean(MappedByteBuffer(byte_buffer))
```

Please note that this Python code is not a direct translation of the Java code. It's more like an equivalent implementation using Python syntax and features.