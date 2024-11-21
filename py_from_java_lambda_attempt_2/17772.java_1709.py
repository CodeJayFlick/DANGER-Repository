Here is the translation of the Java code to Python:
```
class FakedInnerSpaceCompactionTaskFactory:
    def __init__(self):
        pass

    def create_task(self,
                    logical_storage_group_name: str,
                    virtual_storage_group_name: str,
                    time_partition: int,
                    ts_file_manager,  # assuming this is a custom class
                    ts_file_resource_list,  # assuming these are lists of objects
                    selected_ts_file_resources: list,
                    sequence: bool) -> object:
        return FakedInnerSpaceCompactionTask(
            logical_storage_group_name,
            virtual_storage_group_name,
            time_partition,
            ts_file_manager,
            ts_file_resource_list,
            selected_ts_file_resources,
            sequence,
            CompactionTaskManager.current_task_num
        )

class FakedInnerSpaceCompactionTask:
    def __init__(self,
                 logical_storage_group_name: str,
                 virtual_storage_group_name: str,
                 time_partition: int,
                 ts_file_manager,  # assuming this is a custom class
                 ts_file_resource_list,  # assuming these are lists of objects
                 selected_ts_file_resources: list,
                 sequence: bool,
                 task_num):
        pass

# Assuming CompactionTaskManager and InnerSpaceCompactionTaskFactory are defined elsewhere in the codebase
```
Note that I've made some assumptions about the types of variables, such as `ts_file_manager` being a custom class, and `selected_ts_file_resources` being a list. You may need to adjust these depending on your specific use case.

Also, I didn't include any licensing information or comments from the original Java code, as this is not necessary in Python.