Here is the translation of the Java code to Python:
```python
class FakedCrossSpaceCompactionTask:
    def __init__(self,
                 logical_storage_group_name: str,
                 virtual_storage_group_name: str,
                 time_partition_id: int,
                 merge_resource: object,
                 storage_group_dir: str,
                 seq_ts_file_resource_list: list,
                 unseq_ts_file_resource_list: list,
                 selected_seq_ts_file_resources: list,
                 selected_unseq_ts_file_resources: list,
                 concurrent_merge_count: int):
        super().__init__(
            logical_storage_group_name,
            virtual_storage_group_name,
            time_partition_id,
            merge_resource,
            storage_group_dir,
            seq_ts_file_resource_list,
            unseq_ts_file_resource_list,
            selected_seq_ts_file_resources,
            selected_unseq_ts_file_resources,
            concurrent_merge_count,
            CompactionTaskManager.current_task_num
        )

    def do_compaction(self):
        total_unseq_file_size = 0
        for resource in self.selected_unseq_ts_file_resources:
            total_unseq_file_size += resource.ts_file_size

        avg_size_add_to_seq_file = total_unseq_file_size / len(self.selected_seq_ts_file_resources)
        for resource in self.selected_seq_ts_file_resources:
            (resource).ts_file_size += avg_size_add_to_seq_file
            if isinstance(resource, FakedTsFileResource):
                resource.ts_file_size = (resource).ts_file_size + avg_size_add_to_seq_file

        self.selected_unseq_ts_file_resources.clear()
        self.unseq_ts_file_resource_list.clear()

class CompactionTaskManager:
    current_task_num: int = 0
```
Note that I've used Python's type hints to indicate the expected types of variables and function parameters. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've replaced Java's `@Override` annotation with nothing, since Python doesn't have a direct equivalent. The method overriding mechanism in Python relies on the fact that methods are looked up at runtime based on their name and signature, rather than being explicitly marked as overridden.