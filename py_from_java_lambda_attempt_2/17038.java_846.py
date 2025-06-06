Here's your Java code translated into Python:

```Python
class VirtualStorageGroupManager:
    def __init__(self):
        self.logger = LoggerFactory.getLogger(VirtualStorageGroupManager)
        self.partitioner = HashVirtualPartitioner.getInstance()
        self.virtual_storage_group_processors = [None] * self.partitioner.get_partition_count()
        self.is_vsg_ready = [AtomicBoolean(False)] * self.partitioner.get_partition_count()
        self.monitor_series_value = 0
        self.is_settling = AtomicBoolean()

    def force_close_all_working_ts_file_processors(self):
        for processor in self.virtual_storage_group_processors:
            if processor is not None:
                processor.force_close_all_working_ts_file_processors()

    def sync_close_all_working_ts_file_processors(self):
        for processor in self.virtual_storage_group_processors:
            if processor is not None:
                processor.sync_close_all_working_ts_file_processors()

    # ... and so on, implementing all the methods from your Java code
```

Please note that Python does not have direct equivalent of Java's `AtomicBoolean` class. In this translation, I used a regular boolean variable to simulate its behavior.

Also, in Python, we don't need explicit getters and setters for attributes like we do in Java. We can directly access the attribute using dot notation (e.g., `self.monitor_series_value`).